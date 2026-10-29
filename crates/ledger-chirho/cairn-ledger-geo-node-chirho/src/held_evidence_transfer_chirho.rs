// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Restartable held-side import of the accepted winner's adoption-input evidence.
//!
//! The driver first establishes the winner's durable accepted append barrier from the already
//! completed held-view transfer. It then receives only recipient-bound immutable pages named by
//! the winner-signed manifest. Completion means both evidence families reverified from held-local
//! storage; it grants no adoption, compensation, ref movement, or write authority.
//! The config-pinned journal root authenticates ordinary records; the separate winner control key
//! authenticates the manifest and roots that bind those records to the selected winner.

use super::winner_view_transfer_chirho::{
    call_winner_view_transfer_chirho, Gd7WinnerViewTransferCallContextChirho,
    Gd7WinnerViewTransferOperationChirho, Gd7WinnerViewTransferRefusalCodeChirho,
    Gd7WinnerViewTransferResultChirho,
};
use anyhow::{anyhow, bail, Context, Result};
use cairn_config_chirho::config_chirho::LedgerHostConfigChirho;
use cairn_ledger_host_chirho::reconciliation_chirho::{
    gd7_winner_handoff_attempt_digest_chirho,
    load_authenticated_active_gd7_reconciliation_for_group_chirho,
    parse_canonical_gd7_winner_current_view_challenge_chirho, ActiveGd7HeldEvidenceTransferChirho,
    ActiveGd7HeldViewTransferChirho, ExistingNodeGd7SignerChirho,
    Gd7HeldEvidenceTransferIdentityChirho, Gd7HeldEvidenceTransferPhaseChirho,
    Gd7HeldEvidenceTransferStoreChirho, Gd7HeldViewTransferPhaseChirho,
    Gd7HeldViewTransferStoreChirho, Gd7ReconciliationPhaseChirho, Gd7WinnerEvidenceManifestChirho,
    Gd7WinnerEvidencePageTransferChirho, Gd7WinnerHandoffAttemptIdentityChirho,
    Gd7WinnerHandoffPhaseChirho, PinnedNodeGd7VerifierChirho,
};
use cairn_ledger_host_chirho::{
    configured_held_gd7_journal_verifier_chirho, FsLedgerStorageChirho,
    ResidentGd7HeldAdoptionMaterializationRequestChirho, ResidentGd7HeldCoordinatorHandleChirho,
    ResidentGd7HeldCoordinatorRefusalChirho, ResidentGd7HeldCoordinatorSnapshotChirho,
};
use cairn_writer_elector_chirho::elector_port_chirho::{LeadershipChirho, NodeIdChirho};
use cairn_writer_elector_chirho::raft_elector_chirho::RaftWriterElectorChirho;
use std::error::Error;
use std::fmt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

const GD7_HELD_EVIDENCE_TRANSFER_REQUEST_TIMEOUT_CHIRHO: Duration = Duration::from_secs(2);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Gd7HeldHandoffTermDispositionChirho {
    ReuseRetainedAcceptedChirho,
    BeginAtHistoricalTermChirho,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Gd7HeldHandoffContinuationRefusalChirho {
    NewerWinnerTermWithoutRetainedBarrierChirho,
}

impl fmt::Display for Gd7HeldHandoffContinuationRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NewerWinnerTermWithoutRetainedBarrierChirho => formatter_chirho
                .write_str("newer winner term lacks the exact retained accepted handoff barrier"),
        }
    }
}

impl Error for Gd7HeldHandoffContinuationRefusalChirho {}

pub(super) fn invoke_actor_owned_adoption_materialization_chirho<PreparedChirho>(
    identity_chirho: &Gd7HeldEvidenceTransferIdentityChirho,
    evidence_checkpoint_ref_chirho: &str,
    prepare_chirho: impl FnOnce(
        ResidentGd7HeldAdoptionMaterializationRequestChirho,
    ) -> std::result::Result<
        PreparedChirho,
        ResidentGd7HeldCoordinatorRefusalChirho,
    >,
) -> Result<PreparedChirho> {
    prepare_chirho(ResidentGd7HeldAdoptionMaterializationRequestChirho {
        transfer_identity_chirho: identity_chirho.clone(),
        expected_evidence_checkpoint_ref_chirho: evidence_checkpoint_ref_chirho.to_owned(),
    })
    .map_err(|error_chirho| anyhow!("held GD7 adoption materialization refused: {error_chirho}"))
}

pub(super) fn drive_held_evidence_transfer_chirho(
    selected_root_chirho: &Path,
    ledger_host_config_chirho: &LedgerHostConfigChirho,
    winner_base_url_chirho: &str,
    coordinator_chirho: &ResidentGd7HeldCoordinatorHandleChirho,
    elector_chirho: &RaftWriterElectorChirho,
    completed_view_chirho: &ActiveGd7HeldViewTransferChirho,
    stop_chirho: &AtomicBool,
) -> Result<ActiveGd7HeldEvidenceTransferChirho> {
    let baseline_chirho = coordinator_chirho
        .inspect_chirho()
        .context("inspect held coordinate before adoption-evidence transfer")?;
    require_completed_view_binding_chirho(completed_view_chirho, &baseline_chirho)?;

    let held_node_chirho = NodeIdChirho(baseline_chirho.held_node_chirho.clone());
    let winner_node_chirho = NodeIdChirho(baseline_chirho.winner_node_chirho.clone());
    let storage_chirho = FsLedgerStorageChirho::open_existing_chirho(selected_root_chirho)
        .context("open held storage for adoption-evidence transfer")?;
    let held_signer_chirho =
        ExistingNodeGd7SignerChirho::open_existing_chirho(selected_root_chirho, &held_node_chirho)
            .context("open held signer for adoption-evidence checkpoints")?;
    let winner_verifier_chirho =
        PinnedNodeGd7VerifierChirho::new_chirho(winner_node_chirho.clone())
            .context("pin winner control verifier for adoption evidence")?;
    let winner_ledger_verifier_chirho = configured_held_gd7_journal_verifier_chirho(
        ledger_host_config_chirho,
        &winner_node_chirho.0,
    )
    .context("load configured journal verifier for adoption evidence")?;

    let view_store_chirho = Gd7HeldViewTransferStoreChirho::new_chirho(
        &storage_chirho,
        &held_signer_chirho,
        &winner_verifier_chirho,
        completed_view_chirho
            .checkpoint_chirho
            .identity_chirho
            .clone(),
    )
    .context("open exact held-view transfer store")?;
    require_exact_completed_view_chirho(&view_store_chirho, completed_view_chirho)?;

    let active_reconciliation_chirho =
        load_authenticated_active_gd7_reconciliation_for_group_chirho(
            &storage_chirho,
            &held_signer_chirho,
            &baseline_chirho.consistency_group_digest_chirho,
        )
        .context("load authenticated sealed reconciliation for adoption evidence")?
        .ok_or_else(|| anyhow!("sealed held reconciliation is missing"))?;
    if active_reconciliation_chirho.checkpoint_ref_chirho != baseline_chirho.checkpoint_ref_chirho
        || active_reconciliation_chirho
            .checkpoint_chirho
            .state_chirho
            .phase_chirho
            != Gd7ReconciliationPhaseChirho::PlanSealedChirho
    {
        bail!("held reconciliation changed before adoption-evidence transfer");
    }
    require_reconciliation_snapshot_binding_chirho(
        &active_reconciliation_chirho
            .checkpoint_chirho
            .identity_chirho,
        &baseline_chirho,
    )?;

    let agent_chirho = ureq::AgentBuilder::new()
        .timeout(GD7_HELD_EVIDENCE_TRANSFER_REQUEST_TIMEOUT_CHIRHO)
        .build();
    let handoff_status_chirho = establish_accepted_handoff_chirho(
        &agent_chirho,
        winner_base_url_chirho,
        &held_signer_chirho,
        &winner_node_chirho,
        view_store_chirho.identity_digest_chirho(),
        &baseline_chirho,
        elector_chirho,
        coordinator_chirho,
        &view_store_chirho,
        completed_view_chirho,
        &active_reconciliation_chirho.checkpoint_chirho,
    )?;

    let expected_identity_chirho = Gd7HeldEvidenceTransferIdentityChirho {
        reconciliation_identity_chirho: active_reconciliation_chirho
            .checkpoint_chirho
            .identity_chirho
            .clone(),
        reconciliation_checkpoint_ref_chirho: baseline_chirho.checkpoint_ref_chirho.clone(),
        held_view_transfer_checkpoint_ref_chirho: completed_view_chirho
            .checkpoint_ref_chirho
            .clone(),
        winner_handoff_attempt_digest_chirho: handoff_status_chirho.attempt_digest_chirho.clone(),
    };
    let manifest_chirho = prepare_manifest_chirho(
        &agent_chirho,
        winner_base_url_chirho,
        &held_signer_chirho,
        &winner_node_chirho,
        view_store_chirho.identity_digest_chirho(),
        &baseline_chirho,
        elector_chirho,
        coordinator_chirho,
        &view_store_chirho,
        completed_view_chirho,
        &handoff_status_chirho.checkpoint_ref_chirho,
        stop_chirho,
    )?;
    if manifest_chirho.transfer_identity_chirho != expected_identity_chirho {
        bail!("winner adoption-evidence manifest differs from the accepted held coordinate");
    }

    let evidence_store_chirho = Gd7HeldEvidenceTransferStoreChirho::new_chirho(
        &storage_chirho,
        &held_signer_chirho,
        &winner_verifier_chirho,
        &winner_ledger_verifier_chirho,
        expected_identity_chirho,
    )
    .context("open held adoption-evidence transfer store")?;
    let mut active_chirho = evidence_store_chirho
        .begin_chirho(&manifest_chirho)
        .context("initialize or resume held adoption-evidence transfer")?;

    loop {
        if stop_chirho.load(Ordering::Acquire) {
            bail!("held adoption-evidence transfer stopped before completion");
        }
        require_exact_held_coordinate_chirho(
            coordinator_chirho,
            &baseline_chirho,
            &view_store_chirho,
            completed_view_chirho,
        )?;
        match active_chirho.checkpoint_chirho.phase_chirho {
            Gd7HeldEvidenceTransferPhaseChirho::ReceivingChirho => {
                let grant_chirho = active_chirho
                    .checkpoint_chirho
                    .next_grant_chirho()
                    .cloned()
                    .ok_or_else(|| anyhow!("receiving evidence checkpoint omits its next grant"))?;
                let operation_chirho =
                    Gd7WinnerViewTransferOperationChirho::FetchAdoptionEvidencePageChirho {
                        grant_chirho: Box::new(grant_chirho.clone()),
                    };
                let request_nonce_chirho = deterministic_evidence_request_nonce_chirho(
                    &active_chirho.checkpoint_ref_chirho,
                    &operation_chirho,
                    0,
                )?;
                let reply_chirho = call_winner_view_transfer_chirho(
                    Gd7WinnerViewTransferCallContextChirho {
                        agent_chirho: &agent_chirho,
                        base_url_chirho: winner_base_url_chirho,
                        consistency_group_digest_chirho: &baseline_chirho
                            .consistency_group_digest_chirho,
                        sender_signer_chirho: &held_signer_chirho,
                        winner_node_chirho: &winner_node_chirho,
                        transfer_identity_digest_chirho: view_store_chirho.identity_digest_chirho(),
                        expected_raft_term_chirho: current_winner_transport_term_chirho(
                            elector_chirho,
                            &winner_node_chirho,
                            baseline_chirho.winner_term_chirho,
                        )?,
                        request_nonce_chirho: &request_nonce_chirho,
                    },
                    operation_chirho,
                )
                .context("fetch one granted winner adoption-evidence page")?;
                require_exact_held_coordinate_chirho(
                    coordinator_chirho,
                    &baseline_chirho,
                    &view_store_chirho,
                    completed_view_chirho,
                )?;
                active_chirho = match reply_chirho.result_chirho {
                    Gd7WinnerViewTransferResultChirho::AdoptionEvidencePageFetchedChirho {
                        grant_chirho: returned_grant_chirho,
                        next_grant_chirho,
                    } => evidence_store_chirho
                        .receive_page_chirho(
                            &active_chirho.checkpoint_ref_chirho,
                            &Gd7WinnerEvidencePageTransferChirho {
                                grant_chirho: returned_grant_chirho,
                                canonical_page_bytes_chirho: reply_chirho
                                    .canonical_page_bytes_chirho,
                                next_grant_chirho,
                            },
                        )
                        .context(
                            "verify and retain one held-local winner adoption-evidence page",
                        )?,
                    Gd7WinnerViewTransferResultChirho::RefusedChirho { code_chirho } => {
                        return Err(winner_refusal_chirho(
                            "fetch adoption-evidence page",
                            code_chirho,
                        ));
                    }
                    _ => bail!("winner returned an unexpected adoption-evidence page result"),
                };
            }
            Gd7HeldEvidenceTransferPhaseChirho::CompleteChirho => {
                require_exact_held_coordinate_chirho(
                    coordinator_chirho,
                    &baseline_chirho,
                    &view_store_chirho,
                    completed_view_chirho,
                )?;
                return Ok(active_chirho);
            }
        }
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "the request binds one exact held view, sealed plan, winner term and actor barrier"
)]
fn establish_accepted_handoff_chirho(
    agent_chirho: &ureq::Agent,
    winner_base_url_chirho: &str,
    held_signer_chirho: &ExistingNodeGd7SignerChirho,
    winner_node_chirho: &NodeIdChirho,
    transfer_identity_digest_chirho: &str,
    baseline_chirho: &ResidentGd7HeldCoordinatorSnapshotChirho,
    elector_chirho: &RaftWriterElectorChirho,
    coordinator_chirho: &ResidentGd7HeldCoordinatorHandleChirho,
    view_store_chirho: &Gd7HeldViewTransferStoreChirho<'_>,
    completed_view_chirho: &ActiveGd7HeldViewTransferChirho,
    reconciliation_checkpoint_chirho: &cairn_ledger_host_chirho::reconciliation_chirho::Gd7ReconciliationCheckpointChirho,
) -> Result<cairn_ledger_host_chirho::ResidentGd7WinnerHandoffStatusChirho> {
    let canonical_challenge_chirho = completed_view_chirho
        .checkpoint_chirho
        .canonical_challenge_chirho
        .clone()
        .ok_or_else(|| anyhow!("complete held view omits its canonical challenge"))?;
    let challenge_chirho = parse_canonical_gd7_winner_current_view_challenge_chirho(
        canonical_challenge_chirho.as_bytes(),
    )
    .context("parse held-view challenge for accepted handoff")?;
    let expected_bundle_root_object_digest_chirho = completed_view_chirho
        .checkpoint_chirho
        .inspection_chirho
        .as_ref()
        .ok_or_else(|| anyhow!("complete held view omits its winner inspection"))?
        .bundle_root_object_digest_chirho
        .clone();
    let expected_attempt_identity_chirho = Gd7WinnerHandoffAttemptIdentityChirho {
        held_transfer_identity_chirho: completed_view_chirho
            .checkpoint_chirho
            .identity_chirho
            .clone(),
        held_transfer_checkpoint_ref_chirho: completed_view_chirho.checkpoint_ref_chirho.clone(),
        expected_bundle_root_object_digest_chirho: expected_bundle_root_object_digest_chirho
            .clone(),
        challenge_digest_chirho: challenge_chirho
            .digest_chirho()
            .context("digest held-view challenge for accepted handoff")?,
    };
    let expected_attempt_digest_chirho =
        gd7_winner_handoff_attempt_digest_chirho(&expected_attempt_identity_chirho)
            .context("digest accepted winner-handoff attempt")?;
    let current_term_chirho = current_winner_transport_term_chirho(
        elector_chirho,
        winner_node_chirho,
        baseline_chirho.winner_term_chirho,
    )?;
    let status_operation_chirho = Gd7WinnerViewTransferOperationChirho::HandoffStatusChirho {
        attempt_digest_chirho: expected_attempt_digest_chirho.clone(),
    };
    let status_nonce_chirho = deterministic_evidence_request_nonce_chirho(
        &completed_view_chirho.checkpoint_ref_chirho,
        &status_operation_chirho,
        0,
    )?;
    let status_reply_chirho = call_winner_view_transfer_chirho(
        Gd7WinnerViewTransferCallContextChirho {
            agent_chirho,
            base_url_chirho: winner_base_url_chirho,
            consistency_group_digest_chirho: &baseline_chirho.consistency_group_digest_chirho,
            sender_signer_chirho: held_signer_chirho,
            winner_node_chirho,
            transfer_identity_digest_chirho,
            expected_raft_term_chirho: current_term_chirho,
            request_nonce_chirho: &status_nonce_chirho,
        },
        status_operation_chirho,
    )
    .context("probe an existing accepted winner append barrier")?;
    require_exact_held_coordinate_chirho(
        coordinator_chirho,
        baseline_chirho,
        view_store_chirho,
        completed_view_chirho,
    )?;
    let retained_status_chirho = match status_reply_chirho.result_chirho {
        Gd7WinnerViewTransferResultChirho::HandoffStatusChirho { status_chirho }
            if status_chirho.phase_chirho == Gd7WinnerHandoffPhaseChirho::AcceptedChirho
                && status_chirho.attempt_digest_chirho == expected_attempt_digest_chirho
                && status_chirho.attempt_identity_chirho == expected_attempt_identity_chirho =>
        {
            Some(*status_chirho)
        }
        Gd7WinnerViewTransferResultChirho::HandoffStatusChirho { status_chirho }
            if status_chirho.phase_chirho == Gd7WinnerHandoffPhaseChirho::PreparingChirho
                && status_chirho.attempt_digest_chirho == expected_attempt_digest_chirho
                && status_chirho.attempt_identity_chirho == expected_attempt_identity_chirho =>
        {
            None
        }
        Gd7WinnerViewTransferResultChirho::RefusedChirho {
            code_chirho: Gd7WinnerViewTransferRefusalCodeChirho::ActorStateChangedChirho,
        } => None,
        Gd7WinnerViewTransferResultChirho::RefusedChirho { code_chirho } => {
            return Err(winner_refusal_chirho(
                "probe accepted winner append barrier",
                code_chirho,
            ));
        }
        _ => bail!("winner returned a foreign or terminal handoff status"),
    };
    match handoff_term_disposition_chirho(
        retained_status_chirho.is_some(),
        baseline_chirho.winner_term_chirho,
        current_term_chirho,
    )? {
        Gd7HeldHandoffTermDispositionChirho::ReuseRetainedAcceptedChirho => {
            return retained_status_chirho
                .ok_or_else(|| anyhow!("retained handoff disposition omitted its exact status"));
        }
        Gd7HeldHandoffTermDispositionChirho::BeginAtHistoricalTermChirho => {}
    }
    let operation_chirho = Gd7WinnerViewTransferOperationChirho::BeginHandoffChirho {
        held_transfer_identity_chirho: Box::new(
            expected_attempt_identity_chirho
                .held_transfer_identity_chirho
                .clone(),
        ),
        reconciliation_checkpoint_chirho: Box::new(reconciliation_checkpoint_chirho.clone()),
        held_transfer_checkpoint_ref_chirho: completed_view_chirho.checkpoint_ref_chirho.clone(),
        held_transfer_checkpoint_chirho: Box::new(completed_view_chirho.checkpoint_chirho.clone()),
        expected_bundle_root_object_digest_chirho,
        canonical_challenge_chirho,
    };
    let request_nonce_chirho = deterministic_evidence_request_nonce_chirho(
        &completed_view_chirho.checkpoint_ref_chirho,
        &operation_chirho,
        0,
    )?;
    let reply_chirho = call_winner_view_transfer_chirho(
        Gd7WinnerViewTransferCallContextChirho {
            agent_chirho,
            base_url_chirho: winner_base_url_chirho,
            consistency_group_digest_chirho: &baseline_chirho.consistency_group_digest_chirho,
            sender_signer_chirho: held_signer_chirho,
            winner_node_chirho,
            transfer_identity_digest_chirho,
            expected_raft_term_chirho: current_term_chirho,
            request_nonce_chirho: &request_nonce_chirho,
        },
        operation_chirho,
    )
    .context("establish accepted winner append barrier")?;
    require_exact_held_coordinate_chirho(
        coordinator_chirho,
        baseline_chirho,
        view_store_chirho,
        completed_view_chirho,
    )?;
    match reply_chirho.result_chirho {
        Gd7WinnerViewTransferResultChirho::HandoffStatusChirho { status_chirho }
            if status_chirho.phase_chirho == Gd7WinnerHandoffPhaseChirho::AcceptedChirho
                && status_chirho.attempt_digest_chirho == expected_attempt_digest_chirho
                && status_chirho.attempt_identity_chirho == expected_attempt_identity_chirho =>
        {
            Ok(*status_chirho)
        }
        Gd7WinnerViewTransferResultChirho::RefusedChirho { code_chirho } => Err(
            winner_refusal_chirho("establish accepted handoff", code_chirho),
        ),
        _ => bail!("winner did not return the exact accepted handoff"),
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "manifest preparation remains bound to one monitored held coordinate"
)]
fn prepare_manifest_chirho(
    agent_chirho: &ureq::Agent,
    winner_base_url_chirho: &str,
    held_signer_chirho: &ExistingNodeGd7SignerChirho,
    winner_node_chirho: &NodeIdChirho,
    transfer_identity_digest_chirho: &str,
    baseline_chirho: &ResidentGd7HeldCoordinatorSnapshotChirho,
    elector_chirho: &RaftWriterElectorChirho,
    coordinator_chirho: &ResidentGd7HeldCoordinatorHandleChirho,
    view_store_chirho: &Gd7HeldViewTransferStoreChirho<'_>,
    completed_view_chirho: &ActiveGd7HeldViewTransferChirho,
    accepted_checkpoint_ref_chirho: &str,
    stop_chirho: &AtomicBool,
) -> Result<Gd7WinnerEvidenceManifestChirho> {
    let mut step_chirho = 0_u64;
    loop {
        if stop_chirho.load(Ordering::Acquire) {
            bail!("held adoption-evidence preparation stopped before manifest completion");
        }
        require_exact_held_coordinate_chirho(
            coordinator_chirho,
            baseline_chirho,
            view_store_chirho,
            completed_view_chirho,
        )?;
        let operation_chirho = Gd7WinnerViewTransferOperationChirho::PrepareAdoptionEvidenceChirho;
        let request_nonce_chirho = deterministic_evidence_request_nonce_chirho(
            accepted_checkpoint_ref_chirho,
            &operation_chirho,
            step_chirho,
        )?;
        let reply_chirho = call_winner_view_transfer_chirho(
            Gd7WinnerViewTransferCallContextChirho {
                agent_chirho,
                base_url_chirho: winner_base_url_chirho,
                consistency_group_digest_chirho: &baseline_chirho.consistency_group_digest_chirho,
                sender_signer_chirho: held_signer_chirho,
                winner_node_chirho,
                transfer_identity_digest_chirho,
                expected_raft_term_chirho: current_winner_transport_term_chirho(
                    elector_chirho,
                    winner_node_chirho,
                    baseline_chirho.winner_term_chirho,
                )?,
                request_nonce_chirho: &request_nonce_chirho,
            },
            operation_chirho,
        )
        .context("prepare one bounded winner adoption-evidence step")?;
        require_exact_held_coordinate_chirho(
            coordinator_chirho,
            baseline_chirho,
            view_store_chirho,
            completed_view_chirho,
        )?;
        match reply_chirho.result_chirho {
            Gd7WinnerViewTransferResultChirho::AdoptionEvidenceStageAdvancedChirho => {
                step_chirho = step_chirho
                    .checked_add(1)
                    .ok_or_else(|| anyhow!("adoption-evidence preparation step overflow"))?;
            }
            Gd7WinnerViewTransferResultChirho::AdoptionEvidenceReadyChirho { manifest_chirho } => {
                return Ok(*manifest_chirho)
            }
            Gd7WinnerViewTransferResultChirho::RefusedChirho { code_chirho } => {
                return Err(winner_refusal_chirho(
                    "prepare adoption-evidence manifest",
                    code_chirho,
                ));
            }
            _ => bail!("winner returned an unexpected adoption-evidence preparation result"),
        }
    }
}

fn current_winner_transport_term_chirho(
    elector_chirho: &RaftWriterElectorChirho,
    winner_node_chirho: &NodeIdChirho,
    historical_winner_term_chirho: u64,
) -> Result<u64> {
    let leadership_chirho = elector_chirho.current_leadership_chirho();
    winner_transport_term_from_observation_chirho(
        &leadership_chirho,
        winner_node_chirho,
        historical_winner_term_chirho,
    )
}

pub(super) fn winner_transport_term_from_observation_chirho(
    leadership_chirho: &LeadershipChirho,
    winner_node_chirho: &NodeIdChirho,
    historical_winner_term_chirho: u64,
) -> Result<u64> {
    if leadership_chirho.leader_id_chirho.as_ref() != Some(winner_node_chirho)
        || leadership_chirho.term_chirho < historical_winner_term_chirho
    {
        bail!("held elector does not observe the exact historical winner at a current term");
    }
    Ok(leadership_chirho.term_chirho)
}

pub(super) fn require_original_term_before_begin_chirho(
    historical_winner_term_chirho: u64,
    current_term_chirho: u64,
) -> std::result::Result<(), Gd7HeldHandoffContinuationRefusalChirho> {
    if current_term_chirho != historical_winner_term_chirho {
        return Err(
            Gd7HeldHandoffContinuationRefusalChirho::NewerWinnerTermWithoutRetainedBarrierChirho,
        );
    }
    Ok(())
}

pub(super) fn handoff_term_disposition_chirho(
    has_exact_retained_accepted_chirho: bool,
    historical_winner_term_chirho: u64,
    current_term_chirho: u64,
) -> std::result::Result<Gd7HeldHandoffTermDispositionChirho, Gd7HeldHandoffContinuationRefusalChirho>
{
    if has_exact_retained_accepted_chirho {
        return Ok(Gd7HeldHandoffTermDispositionChirho::ReuseRetainedAcceptedChirho);
    }
    require_original_term_before_begin_chirho(historical_winner_term_chirho, current_term_chirho)?;
    Ok(Gd7HeldHandoffTermDispositionChirho::BeginAtHistoricalTermChirho)
}

fn require_completed_view_binding_chirho(
    completed_view_chirho: &ActiveGd7HeldViewTransferChirho,
    baseline_chirho: &ResidentGd7HeldCoordinatorSnapshotChirho,
) -> Result<()> {
    let identity_chirho = &completed_view_chirho.checkpoint_chirho.identity_chirho;
    if baseline_chirho.phase_chirho != Gd7ReconciliationPhaseChirho::PlanSealedChirho
        || completed_view_chirho.checkpoint_chirho.phase_chirho
            != Gd7HeldViewTransferPhaseChirho::CompleteChirho
        || identity_chirho.consistency_group_digest_chirho
            != baseline_chirho.consistency_group_digest_chirho
        || identity_chirho.reconciliation_checkpoint_ref_chirho
            != baseline_chirho.checkpoint_ref_chirho
        || identity_chirho.winner_node_chirho != baseline_chirho.winner_node_chirho
        || identity_chirho.held_node_chirho != baseline_chirho.held_node_chirho
        || identity_chirho.winner_term_chirho != baseline_chirho.winner_term_chirho
    {
        bail!("complete held view differs from the sealed reconciliation coordinate");
    }
    Ok(())
}

fn require_reconciliation_snapshot_binding_chirho(
    identity_chirho: &cairn_ledger_host_chirho::reconciliation_chirho::Gd7ReconciliationIdentityChirho,
    baseline_chirho: &ResidentGd7HeldCoordinatorSnapshotChirho,
) -> Result<()> {
    if identity_chirho.consistency_group_digest_chirho
        != baseline_chirho.consistency_group_digest_chirho
        || identity_chirho.winner_node_chirho != baseline_chirho.winner_node_chirho
        || identity_chirho.held_node_chirho != baseline_chirho.held_node_chirho
        || identity_chirho.winner_term_chirho != baseline_chirho.winner_term_chirho
        || identity_chirho.losing_journal_tail_chirho.epoch_chirho
            != baseline_chirho.losing_tail_epoch_chirho
        || identity_chirho.losing_journal_tail_chirho.seq_chirho
            != baseline_chirho.losing_tail_seq_chirho
        || identity_chirho
            .losing_journal_tail_chirho
            .record_digest_chirho
            != baseline_chirho.losing_tail_digest_chirho
    {
        bail!("authenticated reconciliation identity differs from the held coordinator snapshot");
    }
    Ok(())
}

fn require_exact_completed_view_chirho(
    view_store_chirho: &Gd7HeldViewTransferStoreChirho<'_>,
    expected_chirho: &ActiveGd7HeldViewTransferChirho,
) -> Result<()> {
    let observed_chirho = view_store_chirho
        .load_active_chirho()
        .context("reload exact held-view transfer checkpoint")?
        .ok_or_else(|| anyhow!("held-view transfer checkpoint is missing"))?;
    if &observed_chirho != expected_chirho {
        bail!("held-view transfer checkpoint changed");
    }
    Ok(())
}

fn require_exact_held_coordinate_chirho(
    coordinator_chirho: &ResidentGd7HeldCoordinatorHandleChirho,
    expected_snapshot_chirho: &ResidentGd7HeldCoordinatorSnapshotChirho,
    view_store_chirho: &Gd7HeldViewTransferStoreChirho<'_>,
    expected_view_chirho: &ActiveGd7HeldViewTransferChirho,
) -> Result<()> {
    let observed_chirho = coordinator_chirho
        .inspect_chirho()
        .context("revalidate held reconciliation coordinate")?;
    if &observed_chirho != expected_snapshot_chirho {
        bail!("held reconciliation coordinate changed during adoption-evidence transfer");
    }
    require_exact_completed_view_chirho(view_store_chirho, expected_view_chirho)
}

fn deterministic_evidence_request_nonce_chirho(
    coordinate_chirho: &str,
    operation_chirho: &Gd7WinnerViewTransferOperationChirho,
    step_chirho: u64,
) -> Result<String> {
    let operation_bytes_chirho =
        serde_json::to_vec(operation_chirho).context("serialize evidence-transfer operation")?;
    let mut hasher_chirho = blake3::Hasher::new();
    hasher_chirho.update(b"cairn-gd7-held-adoption-evidence-request-v1-chirho\0");
    hasher_chirho.update(coordinate_chirho.as_bytes());
    hasher_chirho.update(b"\0");
    hasher_chirho.update(&step_chirho.to_be_bytes());
    hasher_chirho.update(b"\0");
    hasher_chirho.update(&operation_bytes_chirho);
    Ok(hasher_chirho.finalize().to_hex().to_string())
}

fn winner_refusal_chirho(
    operation_chirho: &str,
    code_chirho: Gd7WinnerViewTransferRefusalCodeChirho,
) -> anyhow::Error {
    anyhow!("winner refused {operation_chirho}: {code_chirho:?}")
}

#[cfg(test)]
#[path = "held_evidence_transfer_chirho/transport_tests_chirho.rs"]
mod transport_tests_chirho;
