// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Bounded post-append readback after the resident generation guard is released.
//!
//! Workflows:
//! `spec-chirho/workflows-chirho/distributed-ha-chirho/cf6-regenesis-boundary-chirho.md` and
//! `spec-chirho/workflows-chirho/projection-chirho/cf7-read-composition-design-chirho.md` section 11.
//! The append is already committed before this module runs. Only the read-only reprobe may repeat,
//! and only while the local elector reports self-clearing `TransitionPendingChirho` or
//! `GuardBusyChirho`. Every authority, lease, handoff, poison, identity, and storage refusal remains
//! first-attempt terminal. A successful reacquisition must also name the exact generation and Raft
//! term carried by the committed receipt, so waiting cannot normalize real authority drift.

use super::*;
use cairn_writer_elector_chirho::LocalAppendAuthorityRefusalChirho;
use std::fmt;

const POST_APPEND_REPROBE_CONTENTION_LOG_PREFIX_CHIRHO: &str =
    "CairnResidentPostAppendReprobeContentionChirho";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PostAppendReprobeContentionIdentityChirho {
    TransitionPendingChirho,
    GuardBusyChirho,
}

impl PostAppendReprobeContentionIdentityChirho {
    fn from_refusal_chirho(reason_chirho: LocalAppendAuthorityRefusalChirho) -> Option<Self> {
        match reason_chirho {
            LocalAppendAuthorityRefusalChirho::TransitionPendingChirho => {
                Some(Self::TransitionPendingChirho)
            }
            LocalAppendAuthorityRefusalChirho::GuardBusyChirho => Some(Self::GuardBusyChirho),
            _ => None,
        }
    }

    fn as_str_chirho(self) -> &'static str {
        match self {
            Self::TransitionPendingChirho => "TransitionPendingChirho",
            Self::GuardBusyChirho => "GuardBusyChirho",
        }
    }
}

#[allow(
    clippy::enum_variant_names,
    reason = "the fixed private log labels mirror the resident mutation command kinds"
)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ResidentMutationCommandKindChirho {
    AppendHoldChirho,
    AppendCompensationHoldChirho,
    AppendTerminalChirho,
    CompleteGd7CompensationChirho,
    TestkindLossWitnessCurrentChirho,
    TestkindLossWitnessSustainedChirho,
}

impl ResidentMutationCommandKindChirho {
    fn as_str_chirho(self) -> &'static str {
        match self {
            Self::AppendHoldChirho => "AppendHoldChirho",
            Self::AppendCompensationHoldChirho => "AppendCompensationHoldChirho",
            Self::AppendTerminalChirho => "AppendTerminalChirho",
            Self::CompleteGd7CompensationChirho => "CompleteGd7CompensationChirho",
            Self::TestkindLossWitnessCurrentChirho => "TestkindLossWitnessCurrentChirho",
            Self::TestkindLossWitnessSustainedChirho => "TestkindLossWitnessSustainedChirho",
        }
    }
}

#[derive(Debug)]
pub(super) enum PostAppendReprobeRefusalChirho {
    AuthorityChirho(ResidentLedgerAuthorityRefusalChirho),
    AuthorityChangedChirho,
}

impl fmt::Display for PostAppendReprobeRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuthorityChirho(refusal_chirho) => refusal_chirho.fmt(formatter_chirho),
            Self::AuthorityChangedChirho => formatter_chirho.write_str(
                "resident post-append authority differs from the generation that committed",
            ),
        }
    }
}

/// Re-read the committed tail without repeating the append or accepting authority drift.
pub(super) fn probe_after_committed_append_chirho(
    resident_chirho: &ResidentLedgerAuthorityChirho<'_>,
    append_barrier_state_chirho: &ResidentAppendBarrierRuntimeChirho,
    local_authority_chirho: &LocalAppendAuthorityHandleChirho,
    receipt_chirho: &ResidentLedgerAppendReceiptChirho,
    command_kind_chirho: ResidentMutationCommandKindChirho,
) -> Result<ResidentLedgerAuthorityReadinessChirho, PostAppendReprobeRefusalChirho> {
    let mut first_contention_chirho = None;
    let readiness_chirho = retry_resident_generation_contention_chirho(
        || {
            append_barrier_state_chirho
                .probe_resident_chirho(resident_chirho, local_authority_chirho)
        },
        |refusal_chirho| match refusal_chirho {
            ResidentLedgerAuthorityRefusalChirho::LocalGenerationRefusedChirho {
                reason_chirho,
            } => Some(*reason_chirho),
            _ => None,
        },
        |reason_chirho| {
            if first_contention_chirho.is_none() {
                first_contention_chirho =
                    PostAppendReprobeContentionIdentityChirho::from_refusal_chirho(reason_chirho);
            }
        },
        || std::thread::sleep(RESIDENT_GENERATION_CONTENTION_PAUSE_CHIRHO),
        RESIDENT_GENERATION_CONTENTION_ATTEMPTS_CHIRHO,
    );
    let (outcome_chirho, contention_to_emit_chirho) = finish_post_append_reprobe_chirho(
        readiness_chirho,
        receipt_chirho,
        first_contention_chirho,
    );
    if let Some(identity_chirho) = contention_to_emit_chirho {
        emit_post_append_reprobe_contention_chirho(command_kind_chirho, identity_chirho);
    }
    outcome_chirho
}

fn finish_post_append_reprobe_chirho(
    readiness_chirho: Result<
        ResidentLedgerAuthorityReadinessChirho,
        ResidentLedgerAuthorityRefusalChirho,
    >,
    receipt_chirho: &ResidentLedgerAppendReceiptChirho,
    first_contention_chirho: Option<PostAppendReprobeContentionIdentityChirho>,
) -> (
    Result<ResidentLedgerAuthorityReadinessChirho, PostAppendReprobeRefusalChirho>,
    Option<PostAppendReprobeContentionIdentityChirho>,
) {
    match readiness_chirho {
        Ok(readiness_chirho) => {
            match verify_committed_authority_coordinates_chirho(receipt_chirho, &readiness_chirho) {
                Ok(()) => (Ok(readiness_chirho), first_contention_chirho),
                Err(refusal_chirho) => (Err(refusal_chirho), None),
            }
        }
        Err(refusal_chirho) => {
            let terminal_contention_chirho =
                contention_identity_from_resident_refusal_chirho(&refusal_chirho);
            (
                Err(PostAppendReprobeRefusalChirho::AuthorityChirho(
                    refusal_chirho,
                )),
                terminal_contention_chirho,
            )
        }
    }
}

fn contention_identity_from_resident_refusal_chirho(
    refusal_chirho: &ResidentLedgerAuthorityRefusalChirho,
) -> Option<PostAppendReprobeContentionIdentityChirho> {
    match refusal_chirho {
        ResidentLedgerAuthorityRefusalChirho::LocalGenerationRefusedChirho { reason_chirho } => {
            PostAppendReprobeContentionIdentityChirho::from_refusal_chirho(*reason_chirho)
        }
        _ => None,
    }
}

fn emit_post_append_reprobe_contention_chirho(
    command_kind_chirho: ResidentMutationCommandKindChirho,
    identity_chirho: PostAppendReprobeContentionIdentityChirho,
) {
    eprintln!(
        "{POST_APPEND_REPROBE_CONTENTION_LOG_PREFIX_CHIRHO}:command_kind_chirho={}:identity_chirho={}",
        command_kind_chirho.as_str_chirho(),
        identity_chirho.as_str_chirho()
    );
}

fn verify_committed_authority_coordinates_chirho(
    receipt_chirho: &ResidentLedgerAppendReceiptChirho,
    readiness_chirho: &ResidentLedgerAuthorityReadinessChirho,
) -> Result<(), PostAppendReprobeRefusalChirho> {
    if readiness_chirho.process_generation_chirho != receipt_chirho.process_generation_chirho
        || readiness_chirho.published_raft_term_chirho != receipt_chirho.published_raft_term_chirho
    {
        return Err(PostAppendReprobeRefusalChirho::AuthorityChangedChirho);
    }
    Ok(())
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use cairn_ledger_log_chirho::journal_chirho::AppendReceiptChirho;
    use cairn_ledger_model_chirho::record_chirho::HlcChirho;
    use cairn_writer_head_chirho::writer_head_chirho::WriterFenceTokenChirho;
    use std::collections::VecDeque;

    fn local_refusal_chirho(
        reason_chirho: LocalAppendAuthorityRefusalChirho,
    ) -> ResidentLedgerAuthorityRefusalChirho {
        ResidentLedgerAuthorityRefusalChirho::LocalGenerationRefusedChirho { reason_chirho }
    }

    #[test]
    fn post_append_read_retries_only_both_self_clearing_contention_identities_chirho() {
        let mut outcomes_chirho = VecDeque::from([
            Err(local_refusal_chirho(
                LocalAppendAuthorityRefusalChirho::TransitionPendingChirho,
            )),
            Err(local_refusal_chirho(
                LocalAppendAuthorityRefusalChirho::GuardBusyChirho,
            )),
            Ok(17_u64),
        ]);
        let mut observed_chirho = Vec::new();
        let mut pause_count_chirho = 0_usize;
        let accepted_chirho = retry_resident_generation_contention_chirho(
            || outcomes_chirho.pop_front().expect("canned reprobe remains"),
            |refusal_chirho| match refusal_chirho {
                ResidentLedgerAuthorityRefusalChirho::LocalGenerationRefusedChirho {
                    reason_chirho,
                } => Some(*reason_chirho),
                _ => None,
            },
            |reason_chirho| observed_chirho.push(reason_chirho),
            || pause_count_chirho += 1,
            4,
        )
        .expect("both self-clearing contention identities may clear before the bound");

        assert_eq!(accepted_chirho, 17);
        assert_eq!(pause_count_chirho, 2);
        assert_eq!(
            observed_chirho,
            [
                LocalAppendAuthorityRefusalChirho::TransitionPendingChirho,
                LocalAppendAuthorityRefusalChirho::GuardBusyChirho,
            ]
        );
    }

    #[test]
    fn post_append_read_propagates_every_other_local_refusal_without_retry_chirho() {
        let terminal_refusals_chirho = [
            LocalAppendAuthorityRefusalChirho::AuthorityPoisonedChirho,
            LocalAppendAuthorityRefusalChirho::ElectorDroppedChirho,
            LocalAppendAuthorityRefusalChirho::AuthorityUnavailableChirho,
            LocalAppendAuthorityRefusalChirho::NotLocalLeaderChirho,
            LocalAppendAuthorityRefusalChirho::WarmupLeaseInvalidChirho,
            LocalAppendAuthorityRefusalChirho::NotPromotableVoterChirho,
            LocalAppendAuthorityRefusalChirho::LeadershipTransferInProgressChirho,
            LocalAppendAuthorityRefusalChirho::HandoffActiveChirho,
            LocalAppendAuthorityRefusalChirho::HandoffIdentityMismatchChirho,
            LocalAppendAuthorityRefusalChirho::InvalidHandoffIdentityChirho,
            LocalAppendAuthorityRefusalChirho::HandoffGenerationExhaustedChirho,
            LocalAppendAuthorityRefusalChirho::PublishedRaftTermOutOfRangeChirho,
        ];

        for refusal_chirho in terminal_refusals_chirho {
            let mut attempt_count_chirho = 0_usize;
            let actual_chirho = retry_resident_generation_contention_chirho::<(), _>(
                || {
                    attempt_count_chirho += 1;
                    Err(local_refusal_chirho(refusal_chirho))
                },
                |error_chirho| match error_chirho {
                    ResidentLedgerAuthorityRefusalChirho::LocalGenerationRefusedChirho {
                        reason_chirho,
                    } => Some(*reason_chirho),
                    _ => None,
                },
                |_reason_chirho| panic!("terminal refusal must not be observed as contention"),
                || panic!("terminal refusal must not pause"),
                4,
            )
            .expect_err("every non-contention authority refusal remains terminal");
            assert_eq!(actual_chirho, local_refusal_chirho(refusal_chirho));
            assert_eq!(attempt_count_chirho, 1);
        }

        let mut attempt_count_chirho = 0_usize;
        let migration_chirho = retry_resident_generation_contention_chirho::<(), _>(
            || {
                attempt_count_chirho += 1;
                Err(ResidentLedgerAuthorityRefusalChirho::TenantMigrationSourceFenceActiveChirho)
            },
            |_error_chirho| None,
            |_reason_chirho| panic!("migration refusal is not local contention"),
            || panic!("migration refusal must not pause"),
            4,
        )
        .expect_err("migration fencing remains first-attempt terminal");
        assert_eq!(
            migration_chirho,
            ResidentLedgerAuthorityRefusalChirho::TenantMigrationSourceFenceActiveChirho
        );
        assert_eq!(attempt_count_chirho, 1);
    }

    #[test]
    fn post_append_read_exhaustion_returns_the_original_contention_refusal_chirho() {
        let mut observed_count_chirho = 0_usize;
        let mut pause_count_chirho = 0_usize;
        let refusal_chirho = retry_resident_generation_contention_chirho::<(), _>(
            || {
                Err(local_refusal_chirho(
                    LocalAppendAuthorityRefusalChirho::TransitionPendingChirho,
                ))
            },
            |error_chirho| match error_chirho {
                ResidentLedgerAuthorityRefusalChirho::LocalGenerationRefusedChirho {
                    reason_chirho,
                } => Some(*reason_chirho),
                _ => None,
            },
            |_reason_chirho| observed_count_chirho += 1,
            || pause_count_chirho += 1,
            3,
        )
        .expect_err("persistent contention remains a refusal after the exact bound");
        assert_eq!(
            refusal_chirho,
            local_refusal_chirho(LocalAppendAuthorityRefusalChirho::TransitionPendingChirho)
        );
        assert_eq!(observed_count_chirho, 3);
        assert_eq!(pause_count_chirho, 2);
    }

    fn receipt_chirho(
        process_generation_chirho: u64,
        published_raft_term_chirho: u64,
    ) -> ResidentLedgerAppendReceiptChirho {
        ResidentLedgerAppendReceiptChirho {
            append_chirho: AppendReceiptChirho {
                seq_chirho: 2,
                record_digest_chirho: DigestChirho("a".repeat(64)),
                hlc_chirho: HlcChirho {
                    physical_ms_chirho: 7,
                    logical_chirho: 0,
                },
                epoch_first_record_chirho: None,
            },
            fence_chirho: WriterFenceTokenChirho {
                group_chirho: ConsistencyGroupIdChirho::TenantChirho {
                    tenant_id_chirho: "post-append-reprobe-chirho".to_owned(),
                },
                epoch_chirho: 1,
                issued_at_ms_chirho: 7,
            },
            process_generation_chirho,
            published_raft_term_chirho,
        }
    }

    fn readiness_chirho(
        process_generation_chirho: u64,
        published_raft_term_chirho: u64,
    ) -> ResidentLedgerAuthorityReadinessChirho {
        ResidentLedgerAuthorityReadinessChirho {
            consistency_group_chirho: ConsistencyGroupIdChirho::TenantChirho {
                tenant_id_chirho: "post-append-reprobe-chirho".to_owned(),
            },
            local_node_chirho: NodeIdChirho("b".repeat(64)),
            process_generation_chirho,
            published_raft_term_chirho,
            journal_epoch_chirho: 1,
            membership_epoch_chirho: 1,
            journal_tail_seq_chirho: 2,
            journal_tail_digest_chirho: DigestChirho("a".repeat(64)),
            genesis_digest_chirho: DigestChirho("c".repeat(64)),
            resident_identity_digest_chirho: "resident-post-append-reprobe-chirho".to_owned(),
        }
    }

    #[test]
    fn post_append_read_accepts_only_the_committing_generation_and_term_chirho() {
        let receipt_chirho = receipt_chirho(11, 3);
        verify_committed_authority_coordinates_chirho(&receipt_chirho, &readiness_chirho(11, 3))
            .expect("the exact committing coordinates remain admissible");

        for changed_readiness_chirho in [readiness_chirho(12, 3), readiness_chirho(11, 4)] {
            assert!(matches!(
                verify_committed_authority_coordinates_chirho(
                    &receipt_chirho,
                    &changed_readiness_chirho
                ),
                Err(PostAppendReprobeRefusalChirho::AuthorityChangedChirho)
            ));
        }
    }

    #[test]
    fn contention_and_authority_move_end_as_three_distinct_outcomes_chirho() {
        let receipt_chirho = receipt_chirho(11, 3);
        let (recovered_chirho, recovered_contention_chirho) = finish_post_append_reprobe_chirho(
            Ok(readiness_chirho(11, 3)),
            &receipt_chirho,
            Some(PostAppendReprobeContentionIdentityChirho::TransitionPendingChirho),
        );
        recovered_chirho.expect("same-authority contention recovery may proceed");
        assert_eq!(
            recovered_contention_chirho,
            Some(PostAppendReprobeContentionIdentityChirho::TransitionPendingChirho)
        );

        let (exhausted_chirho, exhausted_contention_chirho) = finish_post_append_reprobe_chirho(
            Err(local_refusal_chirho(
                LocalAppendAuthorityRefusalChirho::GuardBusyChirho,
            )),
            &receipt_chirho,
            Some(PostAppendReprobeContentionIdentityChirho::TransitionPendingChirho),
        );
        assert!(matches!(
            exhausted_chirho,
            Err(PostAppendReprobeRefusalChirho::AuthorityChirho(
                ResidentLedgerAuthorityRefusalChirho::LocalGenerationRefusedChirho {
                    reason_chirho: LocalAppendAuthorityRefusalChirho::GuardBusyChirho,
                }
            ))
        ));
        assert_eq!(
            exhausted_contention_chirho,
            Some(PostAppendReprobeContentionIdentityChirho::GuardBusyChirho)
        );

        let (moved_chirho, moved_contention_chirho) = finish_post_append_reprobe_chirho(
            Ok(readiness_chirho(12, 3)),
            &receipt_chirho,
            Some(PostAppendReprobeContentionIdentityChirho::TransitionPendingChirho),
        );
        assert!(matches!(
            moved_chirho,
            Err(PostAppendReprobeRefusalChirho::AuthorityChangedChirho)
        ));
        assert_eq!(moved_contention_chirho, None);

        let (leadership_refusal_chirho, leadership_contention_chirho) =
            finish_post_append_reprobe_chirho(
                Err(local_refusal_chirho(
                    LocalAppendAuthorityRefusalChirho::NotLocalLeaderChirho,
                )),
                &receipt_chirho,
                Some(PostAppendReprobeContentionIdentityChirho::TransitionPendingChirho),
            );
        assert!(matches!(
            leadership_refusal_chirho,
            Err(PostAppendReprobeRefusalChirho::AuthorityChirho(
                ResidentLedgerAuthorityRefusalChirho::LocalGenerationRefusedChirho {
                    reason_chirho: LocalAppendAuthorityRefusalChirho::NotLocalLeaderChirho,
                }
            ))
        ));
        assert_eq!(leadership_contention_chirho, None);
    }

    #[test]
    fn production_reprobe_is_structurally_after_the_single_append_chirho() {
        let mutation_envelope_source_chirho =
            include_str!("../resident_mutation_chirho/envelope_chirho.rs");
        let append_anchor_chirho = "append_chirho(envelope_chirho.resident_chirho)";
        let reprobe_anchor_chirho = "probe_after_committed_append_chirho(";
        let dense_tail_anchor_chirho =
            "EffectCommitJournalCommittedEvidenceIdentityChirho::JournalDenseTailTransitionEvidencePendingChirho";
        assert_eq!(
            mutation_envelope_source_chirho
                .matches(reprobe_anchor_chirho)
                .count(),
            1
        );
        let append_offset_chirho = mutation_envelope_source_chirho
            .find(append_anchor_chirho)
            .expect("the effect append remains in the resident mutation envelope");
        let reprobe_offset_chirho = mutation_envelope_source_chirho
            .find(reprobe_anchor_chirho)
            .expect("the post-append-only reprobe remains wired");
        let dense_tail_offset_chirho = mutation_envelope_source_chirho
            .find(dense_tail_anchor_chirho)
            .expect("the independent dense-tail check remains after the reprobe");
        assert!(append_offset_chirho < reprobe_offset_chirho);
        assert!(reprobe_offset_chirho < dense_tail_offset_chirho);
    }

    #[test]
    fn contention_log_vocabulary_is_fixed_and_two_way_chirho() {
        assert_eq!(
            PostAppendReprobeContentionIdentityChirho::TransitionPendingChirho.as_str_chirho(),
            "TransitionPendingChirho"
        );
        assert_eq!(
            PostAppendReprobeContentionIdentityChirho::GuardBusyChirho.as_str_chirho(),
            "GuardBusyChirho"
        );
        assert_eq!(
            [
                ResidentMutationCommandKindChirho::AppendHoldChirho,
                ResidentMutationCommandKindChirho::AppendCompensationHoldChirho,
                ResidentMutationCommandKindChirho::AppendTerminalChirho,
                ResidentMutationCommandKindChirho::CompleteGd7CompensationChirho,
            ]
            .map(ResidentMutationCommandKindChirho::as_str_chirho),
            [
                "AppendHoldChirho",
                "AppendCompensationHoldChirho",
                "AppendTerminalChirho",
                "CompleteGd7CompensationChirho",
            ]
        );
    }

    #[test]
    fn mutation_command_kind_stays_paired_with_its_dispatch_branch_chirho() {
        let dispatch_source_chirho = include_str!("command_dispatch_chirho.rs");
        let pairings_chirho = [
            (
                "ResidentEffectJournalCommandChirho::AppendHoldChirho {",
                "ResidentEffectJournalCommandChirho::AppendCompensationHoldChirho {",
                "ResidentMutationCommandKindChirho::AppendHoldChirho,",
            ),
            (
                "ResidentEffectJournalCommandChirho::AppendCompensationHoldChirho {",
                "ResidentEffectJournalCommandChirho::AdvanceGd7SinkTermChirho {",
                "ResidentMutationCommandKindChirho::AppendCompensationHoldChirho,",
            ),
            (
                "ResidentEffectJournalCommandChirho::AppendTerminalChirho {",
                "ResidentEffectJournalCommandChirho::ExecuteGd7CompensationProviderChirho {",
                "ResidentMutationCommandKindChirho::AppendTerminalChirho,",
            ),
            (
                "Gd7CompensationCompletionPlanChirho::AppendThenFinishChirho => {",
                "Gd7CompensationCompletionPlanChirho::FinishWithoutAppendChirho => None,",
                "ResidentMutationCommandKindChirho::CompleteGd7CompensationChirho,",
            ),
        ];
        for (branch_chirho, next_branch_chirho, command_kind_chirho) in pairings_chirho {
            let branch_offset_chirho = dispatch_source_chirho
                .find(branch_chirho)
                .expect("the resident mutation dispatch branch remains present");
            let branch_tail_chirho = &dispatch_source_chirho[branch_offset_chirho..];
            let next_offset_chirho = branch_tail_chirho
                .find(next_branch_chirho)
                .expect("the next dispatch boundary remains present");
            assert_eq!(
                branch_tail_chirho[..next_offset_chirho]
                    .matches(command_kind_chirho)
                    .count(),
                1,
                "mutation command kind no longer names its dispatch branch: {branch_chirho}"
            );
        }
    }
}
