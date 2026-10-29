// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Restartable held-side driver for the private GD7 winner-view transfer surface.
//!
//! Every semantic request coordinate is already present in the held-signed checkpoint before the
//! network call. Authority is rechecked before and after each call. This driver receives evidence
//! only; it cannot adopt, compensate, move refs, append effects, or re-enable writes.

use super::winner_view_transfer_chirho::{
    call_winner_view_transfer_chirho, Gd7WinnerViewTransferCallContextChirho,
    Gd7WinnerViewTransferOperationChirho, Gd7WinnerViewTransferRefusalCodeChirho,
    Gd7WinnerViewTransferResultChirho,
};
use anyhow::{anyhow, bail, Context, Result};
use cairn_ledger_host_chirho::reconciliation_chirho::{
    generate_gd7_winner_current_view_challenge_chirho, ActiveGd7HeldViewTransferChirho,
    ExistingNodeGd7SignerChirho, Gd7HeldViewTransferIdentityChirho, Gd7HeldViewTransferPhaseChirho,
    Gd7HeldViewTransferStaleReasonChirho, Gd7HeldViewTransferStoreChirho,
    PinnedNodeGd7VerifierChirho,
};
use cairn_ledger_host_chirho::{
    FsLedgerStorageChirho, ResidentGd7HeldCoordinatorHandleChirho,
    ResidentGd7HeldCoordinatorSnapshotChirho,
};
use cairn_writer_elector_chirho::elector_port_chirho::NodeIdChirho;
use cairn_writer_elector_chirho::raft_elector_chirho::RaftWriterElectorChirho;
use cairn_writer_head_chirho::writer_head_chirho::ConsistencyGroupIdChirho;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

const GD7_HELD_VIEW_TRANSFER_REQUEST_TIMEOUT_CHIRHO: Duration = Duration::from_secs(2);

pub(super) fn drive_held_view_transfer_chirho(
    selected_root_chirho: &Path,
    group_chirho: &ConsistencyGroupIdChirho,
    winner_base_url_chirho: &str,
    coordinator_chirho: &ResidentGd7HeldCoordinatorHandleChirho,
    elector_chirho: &RaftWriterElectorChirho,
    stop_chirho: &AtomicBool,
) -> Result<ActiveGd7HeldViewTransferChirho> {
    let baseline_chirho = coordinator_chirho
        .inspect_chirho()
        .context("inspect held coordinate before opening transfer state")?;
    if baseline_chirho.phase_chirho
        != cairn_ledger_host_chirho::reconciliation_chirho::Gd7ReconciliationPhaseChirho::PlanSealedChirho
    {
        bail!("held winner-view transfer requires a sealed reconciliation plan");
    }
    let held_node_chirho = NodeIdChirho(baseline_chirho.held_node_chirho.clone());
    let winner_node_chirho = NodeIdChirho(baseline_chirho.winner_node_chirho.clone());
    let storage_chirho = FsLedgerStorageChirho::open_existing_chirho(selected_root_chirho)
        .context("open held authority storage for winner-view transfer checkpoints")?;
    let held_signer_chirho =
        ExistingNodeGd7SignerChirho::open_existing_chirho(selected_root_chirho, &held_node_chirho)
            .context("open held signer for winner-view transfer checkpoints")?;
    let winner_verifier_chirho =
        PinnedNodeGd7VerifierChirho::new_chirho(winner_node_chirho.clone())
            .context("pin winner verifier for winner-view transfer")?;
    let store_chirho = Gd7HeldViewTransferStoreChirho::new_chirho(
        &storage_chirho,
        &held_signer_chirho,
        &winner_verifier_chirho,
        Gd7HeldViewTransferIdentityChirho {
            consistency_group_digest_chirho: baseline_chirho
                .consistency_group_digest_chirho
                .clone(),
            reconciliation_checkpoint_ref_chirho: baseline_chirho.checkpoint_ref_chirho.clone(),
            winner_node_chirho: baseline_chirho.winner_node_chirho.clone(),
            held_node_chirho: baseline_chirho.held_node_chirho.clone(),
            winner_term_chirho: baseline_chirho.winner_term_chirho,
        },
    )
    .context("open held winner-view transfer store")?;
    let agent_chirho = ureq::AgentBuilder::new()
        .timeout(GD7_HELD_VIEW_TRANSFER_REQUEST_TIMEOUT_CHIRHO)
        .build();
    let mut active_chirho = store_chirho
        .ensure_initialized_chirho()
        .context("initialize or resume held winner-view transfer")?;

    loop {
        if stop_chirho.load(Ordering::Acquire) {
            return Ok(active_chirho);
        }
        require_exact_held_snapshot_chirho(coordinator_chirho, &baseline_chirho)?;
        match active_chirho.checkpoint_chirho.phase_chirho {
            Gd7HeldViewTransferPhaseChirho::StagingChirho => {
                let expected_stage_index_chirho =
                    active_chirho.checkpoint_chirho.expected_stage_index_chirho;
                let operation_chirho = Gd7WinnerViewTransferOperationChirho::StageOnePageChirho {
                    expected_stage_index_chirho,
                };
                let request_nonce_chirho = deterministic_transfer_request_nonce_chirho(
                    &active_chirho.checkpoint_ref_chirho,
                    &operation_chirho,
                )?;
                let reply_chirho = call_winner_view_transfer_chirho(
                    Gd7WinnerViewTransferCallContextChirho {
                        agent_chirho: &agent_chirho,
                        base_url_chirho: winner_base_url_chirho,
                        consistency_group_digest_chirho: &baseline_chirho
                            .consistency_group_digest_chirho,
                        sender_signer_chirho: &held_signer_chirho,
                        winner_node_chirho: &winner_node_chirho,
                        transfer_identity_digest_chirho: store_chirho.identity_digest_chirho(),
                        expected_raft_term_chirho: baseline_chirho.winner_term_chirho,
                        request_nonce_chirho: &request_nonce_chirho,
                    },
                    operation_chirho,
                )
                .context("request one bounded winner-view staging step")?;
                require_exact_after_network_chirho(
                    coordinator_chirho,
                    &baseline_chirho,
                    &store_chirho,
                    &active_chirho,
                )?;
                active_chirho = match reply_chirho.result_chirho {
                    Gd7WinnerViewTransferResultChirho::StageAdvancedChirho => {
                        active_from_committed_chirho(
                            store_chirho
                                .commit_stage_advanced_chirho(
                                    &active_chirho.checkpoint_ref_chirho,
                                    expected_stage_index_chirho,
                                )
                                .context("checkpoint one winner-view staging step")?,
                        )
                    }
                    Gd7WinnerViewTransferResultChirho::StageReadyChirho {
                        bundle_root_object_digest_chirho,
                        page_count_chirho,
                        row_count_chirho,
                    } => {
                        let issued_challenge_chirho =
                            generate_gd7_winner_current_view_challenge_chirho(
                                elector_chirho,
                                group_chirho,
                                &winner_node_chirho,
                                &held_node_chirho,
                                store_chirho.identity_digest_chirho(),
                            )
                            .context("generate fresh held winner-view challenge")?;
                        let canonical_challenge_chirho = issued_challenge_chirho
                            .canonical_bytes_chirho()
                            .context("canonicalize held winner-view challenge")?;
                        require_exact_held_snapshot_chirho(coordinator_chirho, &baseline_chirho)?;
                        active_from_committed_chirho(
                            store_chirho
                                .commit_challenge_issued_chirho(
                                    &active_chirho.checkpoint_ref_chirho,
                                    expected_stage_index_chirho,
                                    bundle_root_object_digest_chirho,
                                    page_count_chirho,
                                    row_count_chirho,
                                    &canonical_challenge_chirho,
                                )
                                .context("persist challenge before sending it")?,
                        )
                    }
                    Gd7WinnerViewTransferResultChirho::RefusedChirho { code_chirho } => {
                        handle_winner_refusal_chirho(&store_chirho, &active_chirho, code_chirho)?
                    }
                    _ => refuse_without_stale_chirho(
                        &active_chirho,
                        "unexpected signed staging response",
                    )?,
                };
            }
            Gd7HeldViewTransferPhaseChirho::ChallengeIssuedChirho => {
                let canonical_challenge_chirho = active_chirho
                    .checkpoint_chirho
                    .canonical_challenge_chirho
                    .clone()
                    .ok_or_else(|| anyhow!("held transfer challenge checkpoint is incomplete"))?;
                let operation_chirho =
                    Gd7WinnerViewTransferOperationChirho::SealCurrentViewChirho {
                        canonical_challenge_chirho,
                    };
                let request_nonce_chirho = deterministic_transfer_request_nonce_chirho(
                    &active_chirho.checkpoint_ref_chirho,
                    &operation_chirho,
                )?;
                let reply_chirho = call_winner_view_transfer_chirho(
                    Gd7WinnerViewTransferCallContextChirho {
                        agent_chirho: &agent_chirho,
                        base_url_chirho: winner_base_url_chirho,
                        consistency_group_digest_chirho: &baseline_chirho
                            .consistency_group_digest_chirho,
                        sender_signer_chirho: &held_signer_chirho,
                        winner_node_chirho: &winner_node_chirho,
                        transfer_identity_digest_chirho: store_chirho.identity_digest_chirho(),
                        expected_raft_term_chirho: baseline_chirho.winner_term_chirho,
                        request_nonce_chirho: &request_nonce_chirho,
                    },
                    operation_chirho,
                )
                .context("request winner-signed current-view seal")?;
                require_exact_after_network_chirho(
                    coordinator_chirho,
                    &baseline_chirho,
                    &store_chirho,
                    &active_chirho,
                )?;
                active_chirho = match reply_chirho.result_chirho {
                    Gd7WinnerViewTransferResultChirho::ViewSealedChirho {
                        inspection_chirho,
                        first_page_grant_chirho,
                    } => active_from_committed_chirho(
                        store_chirho
                            .commit_sealed_chirho(
                                &active_chirho.checkpoint_ref_chirho,
                                inspection_chirho,
                                first_page_grant_chirho,
                            )
                            .context("checkpoint winner-signed seal and first page grant")?,
                    ),
                    Gd7WinnerViewTransferResultChirho::RefusedChirho { code_chirho } => {
                        handle_winner_refusal_chirho(&store_chirho, &active_chirho, code_chirho)?
                    }
                    _ => refuse_without_stale_chirho(
                        &active_chirho,
                        "unexpected signed seal response",
                    )?,
                };
            }
            Gd7HeldViewTransferPhaseChirho::ReceivingChirho => {
                let grant_chirho = active_chirho
                    .checkpoint_chirho
                    .next_page_grant_chirho
                    .clone()
                    .ok_or_else(|| anyhow!("held transfer receiving state omits its page grant"))?;
                let operation_chirho =
                    Gd7WinnerViewTransferOperationChirho::FetchGrantedPageChirho {
                        grant_chirho: Box::new(grant_chirho.clone()),
                    };
                let request_nonce_chirho = deterministic_transfer_request_nonce_chirho(
                    &active_chirho.checkpoint_ref_chirho,
                    &operation_chirho,
                )?;
                let reply_chirho = call_winner_view_transfer_chirho(
                    Gd7WinnerViewTransferCallContextChirho {
                        agent_chirho: &agent_chirho,
                        base_url_chirho: winner_base_url_chirho,
                        consistency_group_digest_chirho: &baseline_chirho
                            .consistency_group_digest_chirho,
                        sender_signer_chirho: &held_signer_chirho,
                        winner_node_chirho: &winner_node_chirho,
                        transfer_identity_digest_chirho: store_chirho.identity_digest_chirho(),
                        expected_raft_term_chirho: baseline_chirho.winner_term_chirho,
                        request_nonce_chirho: &request_nonce_chirho,
                    },
                    operation_chirho,
                )
                .context("fetch one winner-granted immutable page")?;
                require_exact_after_network_chirho(
                    coordinator_chirho,
                    &baseline_chirho,
                    &store_chirho,
                    &active_chirho,
                )?;
                active_chirho = match reply_chirho.result_chirho {
                    Gd7WinnerViewTransferResultChirho::PageFetchedChirho {
                        grant_chirho: returned_grant_chirho,
                        next_grant_chirho,
                    } => active_from_committed_chirho(
                        store_chirho
                            .commit_received_page_chirho(
                                &active_chirho.checkpoint_ref_chirho,
                                returned_grant_chirho,
                                &reply_chirho.canonical_page_bytes_chirho,
                                next_grant_chirho,
                            )
                            .context("persist one immutable winner-view page then advance head")?,
                    ),
                    Gd7WinnerViewTransferResultChirho::RefusedChirho { code_chirho } => {
                        handle_winner_refusal_chirho(&store_chirho, &active_chirho, code_chirho)?
                    }
                    _ => refuse_without_stale_chirho(
                        &active_chirho,
                        "unexpected signed page response",
                    )?,
                };
            }
            Gd7HeldViewTransferPhaseChirho::CompleteChirho => {
                require_exact_held_snapshot_chirho(coordinator_chirho, &baseline_chirho)?;
                return Ok(active_chirho);
            }
            Gd7HeldViewTransferPhaseChirho::StaleChirho => {
                bail!(
                    "held winner-view transfer is stale and requires a new reconciliation identity"
                );
            }
        }
    }
}

fn require_exact_held_snapshot_chirho(
    coordinator_chirho: &ResidentGd7HeldCoordinatorHandleChirho,
    expected_chirho: &ResidentGd7HeldCoordinatorSnapshotChirho,
) -> Result<()> {
    let observed_chirho = coordinator_chirho
        .inspect_chirho()
        .context("revalidate held election/checkpoint/journal coordinate")?;
    if &observed_chirho != expected_chirho {
        bail!("held election/checkpoint/journal coordinate changed");
    }
    Ok(())
}

fn require_exact_after_network_chirho(
    coordinator_chirho: &ResidentGd7HeldCoordinatorHandleChirho,
    expected_chirho: &ResidentGd7HeldCoordinatorSnapshotChirho,
    store_chirho: &Gd7HeldViewTransferStoreChirho<'_>,
    active_chirho: &ActiveGd7HeldViewTransferChirho,
) -> Result<()> {
    if let Err(error_chirho) =
        require_exact_held_snapshot_chirho(coordinator_chirho, expected_chirho)
    {
        store_chirho
            .mark_stale_chirho(
                &active_chirho.checkpoint_ref_chirho,
                Gd7HeldViewTransferStaleReasonChirho::AuthorityDriftChirho,
            )
            .context("record held transfer stale after authority drift")?;
        return Err(error_chirho);
    }
    Ok(())
}

pub(super) fn handle_winner_refusal_chirho(
    store_chirho: &Gd7HeldViewTransferStoreChirho<'_>,
    active_chirho: &ActiveGd7HeldViewTransferChirho,
    code_chirho: Gd7WinnerViewTransferRefusalCodeChirho,
) -> Result<ActiveGd7HeldViewTransferChirho> {
    match code_chirho {
        Gd7WinnerViewTransferRefusalCodeChirho::LeadershipChangedChirho
        | Gd7WinnerViewTransferRefusalCodeChirho::ActorStateChangedChirho => {
            mark_winner_refusal_stale_chirho(store_chirho, active_chirho, code_chirho)
        }
        Gd7WinnerViewTransferRefusalCodeChirho::ActorBusyChirho
        | Gd7WinnerViewTransferRefusalCodeChirho::ActorUnavailableChirho => {
            refuse_without_stale_chirho(
                active_chirho,
                &format!("transient winner actor refusal {code_chirho:?}"),
            )
        }
        Gd7WinnerViewTransferRefusalCodeChirho::InvalidRequestChirho
        | Gd7WinnerViewTransferRefusalCodeChirho::UnauthenticatedPeerChirho
        | Gd7WinnerViewTransferRefusalCodeChirho::ActorRefusedChirho => {
            refuse_without_stale_chirho(
                active_chirho,
                &format!("winner transfer protocol refusal {code_chirho:?}"),
            )
        }
    }
}

fn mark_winner_refusal_stale_chirho(
    store_chirho: &Gd7HeldViewTransferStoreChirho<'_>,
    active_chirho: &ActiveGd7HeldViewTransferChirho,
    code_chirho: Gd7WinnerViewTransferRefusalCodeChirho,
) -> Result<ActiveGd7HeldViewTransferChirho> {
    let stale_chirho = store_chirho
        .mark_stale_chirho(
            &active_chirho.checkpoint_ref_chirho,
            Gd7HeldViewTransferStaleReasonChirho::WinnerRefusedChirho,
        )
        .context("record winner refusal as a stale transfer")?;
    Err(anyhow!(
        "winner state changed for the persisted held transfer coordinate: {code_chirho:?}; stale checkpoint {}",
        stale_chirho.checkpoint_ref_chirho
    ))
}

fn refuse_without_stale_chirho(
    active_chirho: &ActiveGd7HeldViewTransferChirho,
    detail_chirho: &str,
) -> Result<ActiveGd7HeldViewTransferChirho> {
    Err(anyhow!(
        "{detail_chirho}; durable checkpoint {} remains retryable",
        active_chirho.checkpoint_ref_chirho
    ))
}

fn deterministic_transfer_request_nonce_chirho(
    checkpoint_ref_chirho: &str,
    operation_chirho: &Gd7WinnerViewTransferOperationChirho,
) -> Result<String> {
    let operation_bytes_chirho = serde_json::to_vec(operation_chirho)
        .context("serialize transfer operation for replay id")?;
    let mut hasher_chirho = blake3::Hasher::new();
    hasher_chirho.update(b"cairn-gd7-held-view-transfer-request-v1-chirho\0");
    hasher_chirho.update(checkpoint_ref_chirho.as_bytes());
    hasher_chirho.update(b"\0");
    hasher_chirho.update(&operation_bytes_chirho);
    Ok(hasher_chirho.finalize().to_hex().to_string())
}

fn active_from_committed_chirho(
    committed_chirho: cairn_ledger_host_chirho::reconciliation_chirho::CommittedGd7HeldViewTransferChirho,
) -> ActiveGd7HeldViewTransferChirho {
    ActiveGd7HeldViewTransferChirho {
        checkpoint_ref_chirho: committed_chirho.checkpoint_ref_chirho,
        checkpoint_chirho: committed_chirho.checkpoint_chirho,
    }
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    #[test]
    fn request_nonce_is_exactly_replay_stable_and_coordinate_bound_chirho() {
        let operation_chirho = Gd7WinnerViewTransferOperationChirho::StageOnePageChirho {
            expected_stage_index_chirho: 7,
        };
        let first_chirho =
            deterministic_transfer_request_nonce_chirho(&"a".repeat(64), &operation_chirho)
                .expect("derive deterministic request nonce");
        let replay_chirho =
            deterministic_transfer_request_nonce_chirho(&"a".repeat(64), &operation_chirho)
                .expect("derive replay request nonce");
        let other_checkpoint_chirho =
            deterministic_transfer_request_nonce_chirho(&"b".repeat(64), &operation_chirho)
                .expect("derive another checkpoint request nonce");
        let other_operation_chirho = deterministic_transfer_request_nonce_chirho(
            &"a".repeat(64),
            &Gd7WinnerViewTransferOperationChirho::StageOnePageChirho {
                expected_stage_index_chirho: 8,
            },
        )
        .expect("derive another operation request nonce");

        assert_eq!(first_chirho, replay_chirho);
        assert_ne!(first_chirho, other_checkpoint_chirho);
        assert_ne!(first_chirho, other_operation_chirho);
        assert_eq!(first_chirho.len(), 64);
        assert!(first_chirho.bytes().all(
            |byte_chirho| byte_chirho.is_ascii_digit() || (b'a'..=b'f').contains(&byte_chirho)
        ));
    }
}
