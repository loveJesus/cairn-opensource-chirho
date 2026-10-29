// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use super::super::{ResidentLedgerAuthorityChirho, ResidentLedgerAuthorityReadinessChirho};
use super::ResidentEffectJournalCommandChirho;
use crate::reconciliation_chirho::{
    Gd7ForkCoordinateChirho, Gd7JournalTailCoordinateChirho, Gd7ReconciliationIdentityChirho,
    Gd7WinnerCurrentViewChallengeChirho, Gd7WinnerCurrentViewInspectionChirho,
    Gd7WinnerCurrentViewRefusalChirho, Gd7WinnerFirstRecordIndexChirho, Gd7WinnerForkWitnessChirho,
    Gd7WinnerViewBundleRestartChirho, Gd7WinnerViewBundleStageOutcomeChirho,
    Gd7WinnerViewPageGrantChirho, Gd7WinnerViewPageTransferChirho, Gd7WinnerWitnessRefusalChirho,
    Gd7WinnerWitnessStoreChirho, VerifiedGd7WinnerViewBundleRootChirho,
};
use anyhow::{anyhow, Result};
use cairn_writer_elector_chirho::elector_port_chirho::NodeIdChirho;
use cairn_writer_elector_chirho::LocalAppendHandoffPreparationChirho;
use cairn_writer_head_chirho::writer_head_chirho::{
    consistency_group_digest_chirho, split_writer_epoch_chirho,
};
use std::error::Error;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::Arc;
use std::time::Duration;

const MAX_RESIDENT_GD7_WINNER_FORK_REPLY_DURATION_CHIRHO: Duration = Duration::from_secs(3);

#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants must carry the Chirho suffix"
)]
pub enum ResidentGd7WinnerViewStageInspectionChirho {
    AdvancedOnePageChirho,
    ReadyChirho {
        bundle_root_object_digest_chirho: String,
        page_count_chirho: u64,
        row_count_chirho: u64,
    },
}

/// One challenged winner view plus its first grant for the authenticated held requester.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResidentGd7WinnerViewSealChirho {
    pub inspection_chirho: Gd7WinnerCurrentViewInspectionChirho,
    pub first_page_grant_chirho: Option<Gd7WinnerViewPageGrantChirho>,
}

/// Winner-derived evidence for one exact held losing tail.
///
/// The resident actor chooses the authoritative winner term-first record and fork anchor. This
/// value carries signed evidence only; it cannot append, compensate, adopt, move refs, or enable
/// writes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResidentGd7WinnerForkObservationChirho {
    pub identity_chirho: Gd7ReconciliationIdentityChirho,
    pub winner_first_record_index_chirho: Gd7WinnerFirstRecordIndexChirho,
    pub winner_fork_witness_chirho: Gd7WinnerForkWitnessChirho,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants must carry the Chirho suffix"
)]
pub enum ResidentGd7WinnerForkObservationRefusalChirho {
    ActorBusyChirho,
    ActorUnavailableChirho,
    ActorReplyTimedOutChirho,
    TenantMigrationSourceFenceActiveChirho,
    InvalidHeldCoordinateChirho,
    WinnerStateChangedChirho,
    MissingWinnerIndexChirho,
    WitnessChirho(Gd7WinnerWitnessRefusalChirho),
}

impl fmt::Display for ResidentGd7WinnerForkObservationRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ActorBusyChirho => {
                formatter_chirho.write_str("resident GD7 winner actor is busy")
            }
            Self::ActorUnavailableChirho => {
                formatter_chirho.write_str("resident GD7 winner actor is unavailable")
            }
            Self::ActorReplyTimedOutChirho => {
                formatter_chirho.write_str("resident GD7 winner actor reply timed out")
            }
            Self::TenantMigrationSourceFenceActiveChirho => formatter_chirho
                .write_str("tenant migration source fence blocks GD7 winner observation sealing"),
            Self::InvalidHeldCoordinateChirho => {
                formatter_chirho.write_str("held GD7 losing coordinate is invalid")
            }
            Self::WinnerStateChangedChirho => {
                formatter_chirho.write_str("resident GD7 winner state changed")
            }
            Self::MissingWinnerIndexChirho => {
                formatter_chirho.write_str("resident GD7 winner term-first index is missing")
            }
            Self::WitnessChirho(error_chirho) => {
                write!(
                    formatter_chirho,
                    "resident GD7 winner witness refused: {error_chirho}"
                )
            }
        }
    }
}

impl Error for ResidentGd7WinnerForkObservationRefusalChirho {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::WitnessChirho(error_chirho) => Some(error_chirho),
            Self::ActorBusyChirho
            | Self::ActorUnavailableChirho
            | Self::ActorReplyTimedOutChirho
            | Self::TenantMigrationSourceFenceActiveChirho
            | Self::InvalidHeldCoordinateChirho
            | Self::WinnerStateChangedChirho
            | Self::MissingWinnerIndexChirho => None,
        }
    }
}

/// Typed transport-versus-operation refusal from the restricted winner-evidence actor facade.
#[derive(Debug)]
#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants must carry the Chirho suffix"
)]
pub enum ResidentGd7WinnerEvidenceRefusalChirho {
    MailboxFullChirho,
    ActorUnavailableChirho,
    OperationChirho(Gd7WinnerCurrentViewRefusalChirho),
}

impl fmt::Display for ResidentGd7WinnerEvidenceRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MailboxFullChirho => {
                formatter_chirho.write_str("resident winner-evidence mailbox is at capacity")
            }
            Self::ActorUnavailableChirho => {
                formatter_chirho.write_str("resident winner-evidence actor is unavailable")
            }
            Self::OperationChirho(error_chirho) => {
                write!(
                    formatter_chirho,
                    "winner-evidence operation refused: {error_chirho}"
                )
            }
        }
    }
}

impl Error for ResidentGd7WinnerEvidenceRefusalChirho {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::OperationChirho(error_chirho) => Some(error_chirho),
            Self::MailboxFullChirho | Self::ActorUnavailableChirho => None,
        }
    }
}

/// Restricted sender for one resident actor's winner-evidence surface.
///
/// This type deliberately does not implement the effect-journal traits. It can inspect readiness,
/// stage one bounded account-net page, or seal one challenged current view; it cannot append,
/// compensate, move refs, expose a signer/fence/elector, re-enable writes, or own a second actor.
#[derive(Clone)]
pub struct ResidentGd7WinnerEvidenceHandleChirho {
    pub(super) command_sender_chirho: SyncSender<ResidentEffectJournalCommandChirho>,
}

impl ResidentGd7WinnerEvidenceHandleChirho {
    pub fn probe_chirho(&self) -> Result<ResidentLedgerAuthorityReadinessChirho> {
        let (reply_sender_chirho, reply_receiver_chirho) = sync_channel(1);
        self.command_sender_chirho
            .try_send(ResidentEffectJournalCommandChirho::ProbeGd7WinnerChirho {
                reply_chirho: reply_sender_chirho,
            })
            .map_err(winner_command_send_refusal_chirho)?;
        reply_receiver_chirho
            .recv()
            .map_err(|_error_chirho| {
                anyhow!("resident winner-evidence actor stopped before replying")
            })?
            .map_err(anyhow::Error::new)
    }

    /// Seal the resident-selected term-first index and fork witness for one frozen held tail.
    pub fn observe_deposed_fork_chirho(
        &self,
        expected_winner_term_chirho: u64,
        held_node_chirho: NodeIdChirho,
        losing_journal_genesis_digest_chirho: String,
        losing_journal_tail_chirho: Gd7JournalTailCoordinateChirho,
    ) -> std::result::Result<
        ResidentGd7WinnerForkObservationChirho,
        ResidentGd7WinnerForkObservationRefusalChirho,
    > {
        self.observe_deposed_fork_with_timeout_chirho(
            expected_winner_term_chirho,
            held_node_chirho,
            losing_journal_genesis_digest_chirho,
            losing_journal_tail_chirho,
            MAX_RESIDENT_GD7_WINNER_FORK_REPLY_DURATION_CHIRHO,
        )
    }

    fn observe_deposed_fork_with_timeout_chirho(
        &self,
        expected_winner_term_chirho: u64,
        held_node_chirho: NodeIdChirho,
        losing_journal_genesis_digest_chirho: String,
        losing_journal_tail_chirho: Gd7JournalTailCoordinateChirho,
        reply_timeout_chirho: Duration,
    ) -> std::result::Result<
        ResidentGd7WinnerForkObservationChirho,
        ResidentGd7WinnerForkObservationRefusalChirho,
    > {
        let (reply_sender_chirho, reply_receiver_chirho) = sync_channel(1);
        let cancellation_chirho = Arc::new(AtomicBool::new(false));
        self.command_sender_chirho
            .try_send(
                ResidentEffectJournalCommandChirho::ObserveGd7DeposedForkChirho {
                    expected_winner_term_chirho,
                    held_node_chirho,
                    losing_journal_genesis_digest_chirho,
                    losing_journal_tail_chirho,
                    cancellation_chirho: Arc::clone(&cancellation_chirho),
                    reply_chirho: reply_sender_chirho,
                },
            )
            .map_err(|error_chirho| match error_chirho {
                TrySendError::Full(_command_chirho) => {
                    ResidentGd7WinnerForkObservationRefusalChirho::ActorBusyChirho
                }
                TrySendError::Disconnected(_command_chirho) => {
                    ResidentGd7WinnerForkObservationRefusalChirho::ActorUnavailableChirho
                }
            })?;
        match reply_receiver_chirho.recv_timeout(reply_timeout_chirho) {
            Ok(result_chirho) => result_chirho,
            Err(RecvTimeoutError::Timeout) => {
                cancellation_chirho.store(true, Ordering::Release);
                Err(ResidentGd7WinnerForkObservationRefusalChirho::ActorReplyTimedOutChirho)
            }
            Err(RecvTimeoutError::Disconnected) => {
                Err(ResidentGd7WinnerForkObservationRefusalChirho::ActorUnavailableChirho)
            }
        }
    }

    /// Stage at most one fixed projection page under the exact current local generation.
    pub fn stage_next_view_page_chirho(
        &self,
    ) -> Result<ResidentGd7WinnerViewStageInspectionChirho> {
        let (reply_sender_chirho, reply_receiver_chirho) = sync_channel(1);
        self.command_sender_chirho
            .try_send(
                ResidentEffectJournalCommandChirho::StageGd7WinnerViewPageChirho {
                    expected_stage_index_chirho: None,
                    reply_chirho: reply_sender_chirho,
                },
            )
            .map_err(winner_command_send_refusal_chirho)?;
        reply_receiver_chirho
            .recv()
            .map_err(|_error_chirho| {
                anyhow!("resident winner-evidence actor stopped before replying")
            })?
            .map_err(anyhow::Error::new)
    }

    /// Stage one bounded page only when the caller names the actor's exact next index.
    ///
    /// Retrying the immediately preceding index returns its prior result without advancing again.
    pub fn stage_view_page_at_chirho(
        &self,
        expected_stage_index_chirho: u64,
    ) -> std::result::Result<
        ResidentGd7WinnerViewStageInspectionChirho,
        ResidentGd7WinnerEvidenceRefusalChirho,
    > {
        let (reply_sender_chirho, reply_receiver_chirho) = sync_channel(1);
        self.command_sender_chirho
            .try_send(
                ResidentEffectJournalCommandChirho::StageGd7WinnerViewPageChirho {
                    expected_stage_index_chirho: Some(expected_stage_index_chirho),
                    reply_chirho: reply_sender_chirho,
                },
            )
            .map_err(winner_command_typed_send_refusal_chirho)?;
        reply_receiver_chirho
            .recv()
            .map_err(|_error_chirho| {
                ResidentGd7WinnerEvidenceRefusalChirho::ActorUnavailableChirho
            })?
            .map_err(ResidentGd7WinnerEvidenceRefusalChirho::OperationChirho)
    }

    /// Seal one challenged statement only after this actor has staged the complete current bundle.
    pub fn seal_current_view_chirho(
        &self,
        challenge_chirho: Gd7WinnerCurrentViewChallengeChirho,
    ) -> Result<Gd7WinnerCurrentViewInspectionChirho> {
        let (reply_sender_chirho, reply_receiver_chirho) = sync_channel(1);
        self.command_sender_chirho
            .try_send(
                ResidentEffectJournalCommandChirho::SealGd7WinnerCurrentViewChirho {
                    challenge_chirho,
                    reply_chirho: reply_sender_chirho,
                },
            )
            .map_err(winner_command_send_refusal_chirho)?;
        reply_receiver_chirho
            .recv()
            .map_err(|_error_chirho| {
                anyhow!("resident winner-evidence actor stopped before replying")
            })?
            .map_err(anyhow::Error::new)
    }

    /// Atomically seal one challenged view and mint its first grant for the named held node.
    pub fn seal_current_view_for_held_chirho(
        &self,
        challenge_chirho: Gd7WinnerCurrentViewChallengeChirho,
        held_node_chirho: NodeIdChirho,
    ) -> std::result::Result<ResidentGd7WinnerViewSealChirho, ResidentGd7WinnerEvidenceRefusalChirho>
    {
        let (reply_sender_chirho, reply_receiver_chirho) = sync_channel(1);
        self.command_sender_chirho
            .try_send(
                ResidentEffectJournalCommandChirho::SealGd7WinnerCurrentViewForHeldChirho {
                    challenge_chirho,
                    held_node_chirho,
                    reply_chirho: reply_sender_chirho,
                },
            )
            .map_err(winner_command_typed_send_refusal_chirho)?;
        reply_receiver_chirho
            .recv()
            .map_err(|_error_chirho| {
                ResidentGd7WinnerEvidenceRefusalChirho::ActorUnavailableChirho
            })?
            .map_err(ResidentGd7WinnerEvidenceRefusalChirho::OperationChirho)
    }

    /// Mint only the first page grant committed by the actor's latest sealed current view.
    pub fn issue_first_page_grant_chirho(
        &self,
        held_node_chirho: NodeIdChirho,
    ) -> Result<Option<Gd7WinnerViewPageGrantChirho>> {
        let (reply_sender_chirho, reply_receiver_chirho) = sync_channel(1);
        self.command_sender_chirho
            .try_send(
                ResidentEffectJournalCommandChirho::IssueFirstGd7WinnerViewPageGrantChirho {
                    held_node_chirho,
                    reply_chirho: reply_sender_chirho,
                },
            )
            .map_err(winner_command_send_refusal_chirho)?;
        reply_receiver_chirho
            .recv()
            .map_err(|_error_chirho| {
                anyhow!("resident winner-evidence actor stopped before replying")
            })?
            .map_err(anyhow::Error::new)
    }

    /// Fetch only the exact page named by one recipient-bound winner grant.
    pub fn fetch_granted_page_chirho(
        &self,
        requester_chirho: NodeIdChirho,
        grant_chirho: Gd7WinnerViewPageGrantChirho,
    ) -> std::result::Result<Gd7WinnerViewPageTransferChirho, ResidentGd7WinnerEvidenceRefusalChirho>
    {
        let (reply_sender_chirho, reply_receiver_chirho) = sync_channel(1);
        self.command_sender_chirho
            .try_send(
                ResidentEffectJournalCommandChirho::FetchGrantedGd7WinnerViewPageChirho {
                    requester_chirho,
                    grant_chirho,
                    reply_chirho: reply_sender_chirho,
                },
            )
            .map_err(winner_command_typed_send_refusal_chirho)?;
        reply_receiver_chirho
            .recv()
            .map_err(|_error_chirho| {
                ResidentGd7WinnerEvidenceRefusalChirho::ActorUnavailableChirho
            })?
            .map_err(ResidentGd7WinnerEvidenceRefusalChirho::OperationChirho)
    }
}

pub(super) fn observe_resident_gd7_deposed_fork_chirho(
    resident_chirho: &ResidentLedgerAuthorityChirho<'_>,
    winner_store_chirho: &Gd7WinnerWitnessStoreChirho<'_>,
    expected_winner_term_chirho: u64,
    held_node_chirho: &NodeIdChirho,
    losing_journal_genesis_digest_chirho: &str,
    losing_journal_tail_chirho: &Gd7JournalTailCoordinateChirho,
) -> std::result::Result<
    ResidentGd7WinnerForkObservationChirho,
    ResidentGd7WinnerForkObservationRefusalChirho,
> {
    let before_chirho = resident_chirho
        .probe_chirho()
        .map_err(|_| ResidentGd7WinnerForkObservationRefusalChirho::WinnerStateChangedChirho)?;
    if before_chirho.published_raft_term_chirho != expected_winner_term_chirho
        || held_node_chirho == &before_chirho.local_node_chirho
        || losing_journal_genesis_digest_chirho != before_chirho.genesis_digest_chirho.0
    {
        return Err(ResidentGd7WinnerForkObservationRefusalChirho::InvalidHeldCoordinateChirho);
    }
    let losing_term_chirho = u64::from(
        split_writer_epoch_chirho(losing_journal_tail_chirho.epoch_chirho).geo_term_chirho,
    );
    if losing_term_chirho >= before_chirho.published_raft_term_chirho {
        return Err(ResidentGd7WinnerForkObservationRefusalChirho::InvalidHeldCoordinateChirho);
    }
    let group_digest_chirho =
        consistency_group_digest_chirho(&before_chirho.consistency_group_chirho)
            .map_err(|_| ResidentGd7WinnerForkObservationRefusalChirho::WinnerStateChangedChirho)?;
    let verified_index_chirho = winner_store_chirho
        .load_winner_first_record_chirho(
            &group_digest_chirho,
            &before_chirho.local_node_chirho.0,
            before_chirho.published_raft_term_chirho,
            &before_chirho.genesis_digest_chirho.0,
        )
        .map_err(ResidentGd7WinnerForkObservationRefusalChirho::WitnessChirho)?
        .ok_or(ResidentGd7WinnerForkObservationRefusalChirho::MissingWinnerIndexChirho)?;
    let first_record_chirho = &verified_index_chirho.index_chirho().first_record_chirho;
    let fork_anchor_chirho = first_record_chirho
        .anchor_chirho
        .as_ref()
        .ok_or(ResidentGd7WinnerForkObservationRefusalChirho::InvalidHeldCoordinateChirho)?;
    let identity_chirho = Gd7ReconciliationIdentityChirho {
        consistency_group_digest_chirho: group_digest_chirho,
        winner_node_chirho: before_chirho.local_node_chirho.0.clone(),
        held_node_chirho: held_node_chirho.0.clone(),
        winner_term_chirho: before_chirho.published_raft_term_chirho,
        losing_term_chirho,
        winner_journal_genesis_digest_chirho: before_chirho.genesis_digest_chirho.0.clone(),
        winner_journal_tail_chirho: Gd7JournalTailCoordinateChirho {
            epoch_chirho: first_record_chirho.epoch_chirho,
            seq_chirho: first_record_chirho.seq_chirho,
            record_digest_chirho: verified_index_chirho
                .index_chirho()
                .first_record_digest_chirho
                .clone(),
        },
        fork_chirho: Gd7ForkCoordinateChirho {
            epoch_chirho: fork_anchor_chirho.inherited_epoch_chirho,
            seq_chirho: fork_anchor_chirho.inherited_seq_chirho,
            record_digest_chirho: fork_anchor_chirho.inherited_digest_chirho.0.clone(),
        },
        losing_journal_genesis_digest_chirho: losing_journal_genesis_digest_chirho.to_owned(),
        losing_journal_tail_chirho: losing_journal_tail_chirho.clone(),
    };
    let verified_witness_chirho = winner_store_chirho
        .seal_winner_fork_witness_chirho(identity_chirho.clone(), &verified_index_chirho)
        .map_err(ResidentGd7WinnerForkObservationRefusalChirho::WitnessChirho)?;
    let after_chirho = resident_chirho
        .probe_chirho()
        .map_err(|_| ResidentGd7WinnerForkObservationRefusalChirho::WinnerStateChangedChirho)?;
    if after_chirho != before_chirho {
        return Err(ResidentGd7WinnerForkObservationRefusalChirho::WinnerStateChangedChirho);
    }
    Ok(ResidentGd7WinnerForkObservationChirho {
        identity_chirho,
        winner_first_record_index_chirho: verified_index_chirho.index_chirho().clone(),
        winner_fork_witness_chirho: verified_witness_chirho.witness_chirho().clone(),
    })
}

fn winner_command_typed_send_refusal_chirho(
    error_chirho: TrySendError<ResidentEffectJournalCommandChirho>,
) -> ResidentGd7WinnerEvidenceRefusalChirho {
    match error_chirho {
        TrySendError::Full(_command_chirho) => {
            ResidentGd7WinnerEvidenceRefusalChirho::MailboxFullChirho
        }
        TrySendError::Disconnected(_command_chirho) => {
            ResidentGd7WinnerEvidenceRefusalChirho::ActorUnavailableChirho
        }
    }
}

fn winner_command_send_refusal_chirho(
    error_chirho: TrySendError<ResidentEffectJournalCommandChirho>,
) -> anyhow::Error {
    match error_chirho {
        TrySendError::Full(_command_chirho) => {
            anyhow!("resident winner-evidence mailbox is at its fixed capacity")
        }
        TrySendError::Disconnected(_command_chirho) => {
            anyhow!("resident winner-evidence actor is unavailable")
        }
    }
}

#[derive(Default)]
pub(super) struct ResidentGd7WinnerViewStateChirho {
    restart_chirho: Option<Gd7WinnerViewBundleRestartChirho>,
    complete_root_chirho: Option<VerifiedGd7WinnerViewBundleRootChirho>,
    sealed_inspection_chirho: Option<Gd7WinnerCurrentViewInspectionChirho>,
    source_readiness_chirho: Option<super::super::ResidentLedgerAuthorityReadinessChirho>,
    next_stage_index_chirho: u64,
    last_stage_chirho: Option<(u64, ResidentGd7WinnerViewStageInspectionChirho)>,
}

pub(super) fn stage_resident_gd7_winner_view_page_chirho(
    resident_chirho: &ResidentLedgerAuthorityChirho<'_>,
    state_chirho: &mut ResidentGd7WinnerViewStateChirho,
    expected_stage_index_chirho: Option<u64>,
) -> std::result::Result<
    ResidentGd7WinnerViewStageInspectionChirho,
    Gd7WinnerCurrentViewRefusalChirho,
> {
    let readiness_chirho =
        revalidate_resident_gd7_winner_view_state_chirho(resident_chirho, state_chirho)?;
    if let Some(expected_stage_index_chirho) = expected_stage_index_chirho {
        if let Some((last_stage_index_chirho, last_inspection_chirho)) =
            &state_chirho.last_stage_chirho
        {
            if expected_stage_index_chirho == *last_stage_index_chirho {
                return Ok(last_inspection_chirho.clone());
            }
        }
        if expected_stage_index_chirho != state_chirho.next_stage_index_chirho {
            return Err(Gd7WinnerCurrentViewRefusalChirho::StageIndexMismatchChirho);
        }
    }
    if let Some(bundle_root_chirho) = &state_chirho.complete_root_chirho {
        return Ok(ResidentGd7WinnerViewStageInspectionChirho::ReadyChirho {
            bundle_root_object_digest_chirho: bundle_root_chirho.object_digest_chirho().to_owned(),
            page_count_chirho: bundle_root_chirho.root_chirho().page_count_chirho,
            row_count_chirho: bundle_root_chirho.root_chirho().row_count_chirho,
        });
    }
    match resident_chirho
        .stage_next_gd7_winner_view_bundle_page_chirho(state_chirho.restart_chirho.as_ref())
    {
        Ok(Gd7WinnerViewBundleStageOutcomeChirho::ContinueChirho { restart_chirho }) => {
            let request_stage_index_chirho = state_chirho.next_stage_index_chirho;
            let next_stage_index_chirho = request_stage_index_chirho
                .checked_add(1)
                .ok_or(Gd7WinnerCurrentViewRefusalChirho::StageIndexMismatchChirho)?;
            let inspection_chirho =
                ResidentGd7WinnerViewStageInspectionChirho::AdvancedOnePageChirho;
            state_chirho.restart_chirho = Some(restart_chirho);
            state_chirho.source_readiness_chirho = Some(readiness_chirho);
            state_chirho.next_stage_index_chirho = next_stage_index_chirho;
            state_chirho.last_stage_chirho =
                Some((request_stage_index_chirho, inspection_chirho.clone()));
            Ok(inspection_chirho)
        }
        Ok(Gd7WinnerViewBundleStageOutcomeChirho::CompleteChirho { bundle_root_chirho }) => {
            let request_stage_index_chirho = state_chirho.next_stage_index_chirho;
            let next_stage_index_chirho = request_stage_index_chirho
                .checked_add(1)
                .ok_or(Gd7WinnerCurrentViewRefusalChirho::StageIndexMismatchChirho)?;
            let inspection_chirho = ResidentGd7WinnerViewStageInspectionChirho::ReadyChirho {
                bundle_root_object_digest_chirho: bundle_root_chirho
                    .object_digest_chirho()
                    .to_owned(),
                page_count_chirho: bundle_root_chirho.root_chirho().page_count_chirho,
                row_count_chirho: bundle_root_chirho.root_chirho().row_count_chirho,
            };
            state_chirho.restart_chirho = None;
            state_chirho.complete_root_chirho = Some(bundle_root_chirho);
            state_chirho.source_readiness_chirho = Some(readiness_chirho);
            state_chirho.next_stage_index_chirho = next_stage_index_chirho;
            state_chirho.last_stage_chirho =
                Some((request_stage_index_chirho, inspection_chirho.clone()));
            Ok(inspection_chirho)
        }
        Err(Gd7WinnerCurrentViewRefusalChirho::JournalCutMismatchChirho) => {
            *state_chirho = ResidentGd7WinnerViewStateChirho::default();
            Err(Gd7WinnerCurrentViewRefusalChirho::JournalCutMismatchChirho)
        }
        Err(error_chirho) => Err(error_chirho),
    }
}

pub(super) fn seal_resident_gd7_winner_current_view_chirho(
    resident_chirho: &ResidentLedgerAuthorityChirho<'_>,
    state_chirho: &mut ResidentGd7WinnerViewStateChirho,
    challenge_chirho: Gd7WinnerCurrentViewChallengeChirho,
) -> std::result::Result<Gd7WinnerCurrentViewInspectionChirho, Gd7WinnerCurrentViewRefusalChirho> {
    let bundle_root_chirho =
        ready_resident_gd7_winner_view_root_chirho(resident_chirho, state_chirho)?;
    match resident_chirho.seal_gd7_winner_current_view_chirho(challenge_chirho, &bundle_root_chirho)
    {
        Err(Gd7WinnerCurrentViewRefusalChirho::JournalCutMismatchChirho) => {
            *state_chirho = ResidentGd7WinnerViewStateChirho::default();
            Err(Gd7WinnerCurrentViewRefusalChirho::JournalCutMismatchChirho)
        }
        Ok(inspection_chirho) => {
            state_chirho.sealed_inspection_chirho = Some(inspection_chirho.clone());
            Ok(inspection_chirho)
        }
        Err(error_chirho) => Err(error_chirho),
    }
}

pub(super) fn seal_resident_gd7_winner_current_view_for_held_chirho(
    resident_chirho: &ResidentLedgerAuthorityChirho<'_>,
    state_chirho: &mut ResidentGd7WinnerViewStateChirho,
    challenge_chirho: Gd7WinnerCurrentViewChallengeChirho,
    held_node_chirho: &NodeIdChirho,
) -> std::result::Result<ResidentGd7WinnerViewSealChirho, Gd7WinnerCurrentViewRefusalChirho> {
    let inspection_chirho = seal_resident_gd7_winner_current_view_chirho(
        resident_chirho,
        state_chirho,
        challenge_chirho,
    )?;
    let first_page_grant_chirho = issue_first_resident_gd7_winner_view_page_grant_chirho(
        resident_chirho,
        state_chirho,
        held_node_chirho,
    )?;
    Ok(ResidentGd7WinnerViewSealChirho {
        inspection_chirho,
        first_page_grant_chirho,
    })
}

pub(super) fn reseal_resident_gd7_winner_current_view_during_handoff_chirho(
    resident_chirho: &ResidentLedgerAuthorityChirho<'_>,
    state_chirho: &mut ResidentGd7WinnerViewStateChirho,
    preparation_chirho: &LocalAppendHandoffPreparationChirho<'_>,
    challenge_chirho: Gd7WinnerCurrentViewChallengeChirho,
) -> std::result::Result<Gd7WinnerCurrentViewInspectionChirho, Gd7WinnerCurrentViewRefusalChirho> {
    let readiness_chirho = resident_chirho
        .probe_during_handoff_preparation_chirho(preparation_chirho)
        .map_err(|_| Gd7WinnerCurrentViewRefusalChirho::ResidentEvidenceChangedChirho)?;
    validate_resident_gd7_winner_view_readiness_chirho(state_chirho, &readiness_chirho)?;
    let bundle_root_chirho = state_chirho
        .complete_root_chirho
        .clone()
        .ok_or(Gd7WinnerCurrentViewRefusalChirho::MissingBundleRootChirho)?;
    match resident_chirho.seal_gd7_winner_current_view_during_handoff_chirho(
        preparation_chirho,
        challenge_chirho,
        &bundle_root_chirho,
    ) {
        Ok(inspection_chirho) => {
            state_chirho.sealed_inspection_chirho = Some(inspection_chirho.clone());
            Ok(inspection_chirho)
        }
        Err(Gd7WinnerCurrentViewRefusalChirho::JournalCutMismatchChirho) => {
            *state_chirho = ResidentGd7WinnerViewStateChirho::default();
            Err(Gd7WinnerCurrentViewRefusalChirho::JournalCutMismatchChirho)
        }
        Err(error_chirho) => Err(error_chirho),
    }
}

pub(super) fn issue_first_resident_gd7_winner_view_page_grant_chirho(
    resident_chirho: &ResidentLedgerAuthorityChirho<'_>,
    state_chirho: &mut ResidentGd7WinnerViewStateChirho,
    held_node_chirho: &NodeIdChirho,
) -> std::result::Result<Option<Gd7WinnerViewPageGrantChirho>, Gd7WinnerCurrentViewRefusalChirho> {
    let (bundle_root_chirho, sealed_inspection_chirho) =
        ready_sealed_resident_gd7_winner_view_chirho(resident_chirho, state_chirho)?;
    resident_chirho.issue_first_gd7_winner_view_page_grant_chirho(
        held_node_chirho,
        &sealed_inspection_chirho.evidence_object_digest_chirho,
        &bundle_root_chirho,
    )
}

pub(super) fn fetch_resident_gd7_winner_view_page_chirho(
    resident_chirho: &ResidentLedgerAuthorityChirho<'_>,
    state_chirho: &mut ResidentGd7WinnerViewStateChirho,
    requester_chirho: &NodeIdChirho,
    grant_chirho: Gd7WinnerViewPageGrantChirho,
) -> std::result::Result<Gd7WinnerViewPageTransferChirho, Gd7WinnerCurrentViewRefusalChirho> {
    let (bundle_root_chirho, sealed_inspection_chirho) =
        ready_sealed_resident_gd7_winner_view_chirho(resident_chirho, state_chirho)?;
    if grant_chirho.winner_evidence_object_digest_chirho
        != sealed_inspection_chirho.evidence_object_digest_chirho
    {
        return Err(Gd7WinnerCurrentViewRefusalChirho::InvalidPageGrantChirho);
    }
    resident_chirho.fetch_granted_gd7_winner_view_page_chirho(
        requester_chirho,
        &sealed_inspection_chirho.evidence_object_digest_chirho,
        &bundle_root_chirho,
        grant_chirho,
    )
}

fn ready_sealed_resident_gd7_winner_view_chirho(
    resident_chirho: &ResidentLedgerAuthorityChirho<'_>,
    state_chirho: &mut ResidentGd7WinnerViewStateChirho,
) -> std::result::Result<
    (
        VerifiedGd7WinnerViewBundleRootChirho,
        Gd7WinnerCurrentViewInspectionChirho,
    ),
    Gd7WinnerCurrentViewRefusalChirho,
> {
    let bundle_root_chirho =
        ready_resident_gd7_winner_view_root_chirho(resident_chirho, state_chirho)?;
    let sealed_inspection_chirho = state_chirho
        .sealed_inspection_chirho
        .clone()
        .ok_or(Gd7WinnerCurrentViewRefusalChirho::MissingEvidenceChirho)?;
    if sealed_inspection_chirho.bundle_root_object_digest_chirho
        != bundle_root_chirho.object_digest_chirho()
    {
        *state_chirho = ResidentGd7WinnerViewStateChirho::default();
        return Err(Gd7WinnerCurrentViewRefusalChirho::BundleRootMismatchChirho);
    }
    Ok((bundle_root_chirho, sealed_inspection_chirho))
}

fn ready_resident_gd7_winner_view_root_chirho(
    resident_chirho: &ResidentLedgerAuthorityChirho<'_>,
    state_chirho: &mut ResidentGd7WinnerViewStateChirho,
) -> std::result::Result<VerifiedGd7WinnerViewBundleRootChirho, Gd7WinnerCurrentViewRefusalChirho> {
    revalidate_resident_gd7_winner_view_state_chirho(resident_chirho, state_chirho)?;
    state_chirho
        .complete_root_chirho
        .clone()
        .ok_or(Gd7WinnerCurrentViewRefusalChirho::MissingBundleRootChirho)
}

fn revalidate_resident_gd7_winner_view_state_chirho(
    resident_chirho: &ResidentLedgerAuthorityChirho<'_>,
    state_chirho: &mut ResidentGd7WinnerViewStateChirho,
) -> std::result::Result<
    super::super::ResidentLedgerAuthorityReadinessChirho,
    Gd7WinnerCurrentViewRefusalChirho,
> {
    let readiness_chirho = resident_chirho
        .probe_chirho()
        .map_err(|_| Gd7WinnerCurrentViewRefusalChirho::ResidentEvidenceChangedChirho)?;
    validate_resident_gd7_winner_view_readiness_chirho(state_chirho, &readiness_chirho)?;
    Ok(readiness_chirho)
}

fn validate_resident_gd7_winner_view_readiness_chirho(
    state_chirho: &mut ResidentGd7WinnerViewStateChirho,
    readiness_chirho: &super::super::ResidentLedgerAuthorityReadinessChirho,
) -> std::result::Result<(), Gd7WinnerCurrentViewRefusalChirho> {
    let readiness_changed_chirho = state_chirho
        .source_readiness_chirho
        .as_ref()
        .is_some_and(|source_readiness_chirho| source_readiness_chirho != readiness_chirho);
    let root_changed_chirho =
        state_chirho
            .complete_root_chirho
            .as_ref()
            .is_some_and(|bundle_root_chirho| {
                let source_cut_chirho = &bundle_root_chirho.root_chirho().source_cut_chirho;
                bundle_root_chirho
                    .root_chirho()
                    .winner_journal_genesis_digest_chirho
                    .as_str()
                    != readiness_chirho.genesis_digest_chirho.0.as_str()
                    || source_cut_chirho.epoch_chirho != readiness_chirho.journal_epoch_chirho
                    || source_cut_chirho.seq_chirho != readiness_chirho.journal_tail_seq_chirho
                    || source_cut_chirho.record_digest_chirho.as_str()
                        != readiness_chirho.journal_tail_digest_chirho.0.as_str()
            });
    if readiness_changed_chirho || root_changed_chirho {
        *state_chirho = ResidentGd7WinnerViewStateChirho::default();
        return Err(Gd7WinnerCurrentViewRefusalChirho::JournalCutMismatchChirho);
    }
    Ok(())
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use std::time::Instant;

    #[test]
    fn winner_observation_reply_timeout_cancels_queued_work_chirho() {
        let (command_sender_chirho, command_receiver_chirho) = sync_channel(1);
        let handle_chirho = ResidentGd7WinnerEvidenceHandleChirho {
            command_sender_chirho,
        };
        let started_chirho = Instant::now();
        let refusal_chirho = handle_chirho
            .observe_deposed_fork_with_timeout_chirho(
                7,
                NodeIdChirho("held-node-chirho".to_owned()),
                "a".repeat(64),
                Gd7JournalTailCoordinateChirho {
                    epoch_chirho: 6,
                    seq_chirho: 9,
                    record_digest_chirho: "b".repeat(64),
                },
                Duration::from_millis(20),
            )
            .unwrap_err();

        assert_eq!(
            refusal_chirho,
            ResidentGd7WinnerForkObservationRefusalChirho::ActorReplyTimedOutChirho
        );
        assert!(started_chirho.elapsed() < Duration::from_secs(1));
        match command_receiver_chirho.try_recv().unwrap() {
            ResidentEffectJournalCommandChirho::ObserveGd7DeposedForkChirho {
                cancellation_chirho,
                ..
            } => assert!(cancellation_chirho.load(Ordering::Acquire)),
            _other_chirho => panic!("expected one queued winner-observation command"),
        }
    }
}
