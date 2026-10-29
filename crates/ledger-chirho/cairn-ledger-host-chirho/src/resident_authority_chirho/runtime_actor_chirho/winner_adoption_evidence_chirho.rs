// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Resident-actor preparation and serving of accepted GD7 adoption-input evidence.
//!
//! Every operation requires the live runtime's accepted append barrier. The handle receives no
//! storage path, page size, cursor, root digest, adoption target, or authority object.

use super::{
    ResidentEffectJournalCommandChirho, ResidentGd7WinnerHandoffRuntimeChirho,
    ResidentLedgerAuthorityChirho,
};
use crate::reconciliation_chirho::{
    Gd7HeldEvidenceTransferIdentityChirho, Gd7WinnerEvidenceManifestChirho,
    Gd7WinnerEvidencePageGrantChirho, Gd7WinnerEvidencePageTransferChirho,
    Gd7WinnerHandoffStoreChirho, Gd7WinnerHandoffStoreRefusalChirho, Gd7WinnerHistoryRestartChirho,
    Gd7WinnerHistoryStageOutcomeChirho, PinnedNodeGd7VerifierChirho,
    VerifiedGd7WinnerHistoryRootChirho,
};
use cairn_writer_elector_chirho::elector_port_chirho::NodeIdChirho;
use std::error::Error;
use std::fmt;
use std::sync::mpsc::{sync_channel, SyncSender, TrySendError};

#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants must carry the Chirho suffix"
)]
pub enum ResidentGd7WinnerAdoptionEvidenceInspectionChirho {
    AdvancedWinnerHistoryPageChirho,
    ReadyChirho(Box<Gd7WinnerEvidenceManifestChirho>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants must carry the Chirho suffix"
)]
pub enum ResidentGd7WinnerAdoptionEvidenceRefusalChirho {
    MailboxFullChirho,
    ActorUnavailableChirho,
    AcceptedBarrierMissingChirho,
    InvalidRequestChirho,
    StoreChirho(Gd7WinnerHandoffStoreRefusalChirho),
}

impl fmt::Display for ResidentGd7WinnerAdoptionEvidenceRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MailboxFullChirho => formatter_chirho
                .write_str("resident winner adoption-evidence mailbox is at capacity"),
            Self::ActorUnavailableChirho => {
                formatter_chirho.write_str("resident winner adoption-evidence actor is unavailable")
            }
            Self::AcceptedBarrierMissingChirho => formatter_chirho
                .write_str("resident winner adoption evidence lacks a live accepted barrier"),
            Self::InvalidRequestChirho => {
                formatter_chirho.write_str("resident winner adoption-evidence request is invalid")
            }
            Self::StoreChirho(error_chirho) => {
                write!(
                    formatter_chirho,
                    "resident winner adoption evidence refused: {error_chirho}"
                )
            }
        }
    }
}

impl Error for ResidentGd7WinnerAdoptionEvidenceRefusalChirho {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::StoreChirho(error_chirho) => Some(error_chirho),
            _ => None,
        }
    }
}

impl From<Gd7WinnerHandoffStoreRefusalChirho> for ResidentGd7WinnerAdoptionEvidenceRefusalChirho {
    fn from(error_chirho: Gd7WinnerHandoffStoreRefusalChirho) -> Self {
        Self::StoreChirho(error_chirho)
    }
}

pub(super) enum ResidentGd7WinnerAdoptionEvidenceCommandChirho {
    PrepareChirho,
    FetchPageChirho {
        requester_chirho: NodeIdChirho,
        grant_chirho: Gd7WinnerEvidencePageGrantChirho,
    },
}

pub(super) enum ResidentGd7WinnerAdoptionEvidenceReplyChirho {
    InspectionChirho(ResidentGd7WinnerAdoptionEvidenceInspectionChirho),
    PageChirho(Box<Gd7WinnerEvidencePageTransferChirho>),
}

#[derive(Clone)]
pub struct ResidentGd7WinnerAdoptionEvidenceHandleChirho {
    pub(super) command_sender_chirho: SyncSender<ResidentEffectJournalCommandChirho>,
}

impl ResidentGd7WinnerAdoptionEvidenceHandleChirho {
    pub fn prepare_next_chirho(
        &self,
    ) -> Result<
        ResidentGd7WinnerAdoptionEvidenceInspectionChirho,
        ResidentGd7WinnerAdoptionEvidenceRefusalChirho,
    > {
        match self.request_chirho(ResidentGd7WinnerAdoptionEvidenceCommandChirho::PrepareChirho)? {
            ResidentGd7WinnerAdoptionEvidenceReplyChirho::InspectionChirho(inspection_chirho) => {
                Ok(inspection_chirho)
            }
            ResidentGd7WinnerAdoptionEvidenceReplyChirho::PageChirho(
                _evidence_page_transfer_chirho,
            ) => Err(ResidentGd7WinnerAdoptionEvidenceRefusalChirho::InvalidRequestChirho),
        }
    }

    pub fn fetch_page_chirho(
        &self,
        requester_chirho: NodeIdChirho,
        grant_chirho: Gd7WinnerEvidencePageGrantChirho,
    ) -> Result<Gd7WinnerEvidencePageTransferChirho, ResidentGd7WinnerAdoptionEvidenceRefusalChirho>
    {
        match self.request_chirho(
            ResidentGd7WinnerAdoptionEvidenceCommandChirho::FetchPageChirho {
                requester_chirho,
                grant_chirho,
            },
        )? {
            ResidentGd7WinnerAdoptionEvidenceReplyChirho::PageChirho(
                evidence_page_transfer_chirho,
            ) => Ok(*evidence_page_transfer_chirho),
            ResidentGd7WinnerAdoptionEvidenceReplyChirho::InspectionChirho(_inspection_chirho) => {
                Err(ResidentGd7WinnerAdoptionEvidenceRefusalChirho::InvalidRequestChirho)
            }
        }
    }

    fn request_chirho(
        &self,
        command_chirho: ResidentGd7WinnerAdoptionEvidenceCommandChirho,
    ) -> Result<
        ResidentGd7WinnerAdoptionEvidenceReplyChirho,
        ResidentGd7WinnerAdoptionEvidenceRefusalChirho,
    > {
        let (reply_sender_chirho, reply_receiver_chirho) = sync_channel(1);
        self.command_sender_chirho
            .try_send(
                ResidentEffectJournalCommandChirho::Gd7WinnerAdoptionEvidenceChirho {
                    command_chirho,
                    reply_chirho: reply_sender_chirho,
                },
            )
            .map_err(|error_chirho| match error_chirho {
                TrySendError::Full(_command_chirho) => {
                    ResidentGd7WinnerAdoptionEvidenceRefusalChirho::MailboxFullChirho
                }
                TrySendError::Disconnected(_command_chirho) => {
                    ResidentGd7WinnerAdoptionEvidenceRefusalChirho::ActorUnavailableChirho
                }
            })?;
        reply_receiver_chirho.recv().map_err(|_error_chirho| {
            ResidentGd7WinnerAdoptionEvidenceRefusalChirho::ActorUnavailableChirho
        })?
    }
}

#[derive(Default)]
pub(super) struct ResidentGd7WinnerAdoptionEvidenceStateChirho {
    attempt_digest_chirho: Option<String>,
    history_restart_chirho: Option<Gd7WinnerHistoryRestartChirho>,
    history_root_chirho: Option<VerifiedGd7WinnerHistoryRootChirho>,
    manifest_chirho: Option<Gd7WinnerEvidenceManifestChirho>,
}

pub(super) fn handle_resident_gd7_winner_adoption_evidence_chirho(
    command_chirho: ResidentGd7WinnerAdoptionEvidenceCommandChirho,
    resident_chirho: &ResidentLedgerAuthorityChirho<'_>,
    handoff_runtime_chirho: &ResidentGd7WinnerHandoffRuntimeChirho,
    handoff_store_chirho: &Gd7WinnerHandoffStoreChirho<'_>,
    state_chirho: &mut ResidentGd7WinnerAdoptionEvidenceStateChirho,
) -> Result<
    ResidentGd7WinnerAdoptionEvidenceReplyChirho,
    ResidentGd7WinnerAdoptionEvidenceRefusalChirho,
> {
    let accepted_attempt_digest_chirho =
        require_accepted_attempt_digest_chirho(handoff_runtime_chirho)?;
    if state_chirho.attempt_digest_chirho.as_deref() != Some(accepted_attempt_digest_chirho) {
        *state_chirho = ResidentGd7WinnerAdoptionEvidenceStateChirho {
            attempt_digest_chirho: Some(accepted_attempt_digest_chirho.to_owned()),
            ..ResidentGd7WinnerAdoptionEvidenceStateChirho::default()
        };
    }
    match command_chirho {
        ResidentGd7WinnerAdoptionEvidenceCommandChirho::PrepareChirho => {
            prepare_chirho(resident_chirho, handoff_store_chirho, state_chirho)
                .map(ResidentGd7WinnerAdoptionEvidenceReplyChirho::InspectionChirho)
        }
        ResidentGd7WinnerAdoptionEvidenceCommandChirho::FetchPageChirho {
            requester_chirho,
            grant_chirho,
        } => {
            let manifest_chirho = state_chirho
                .manifest_chirho
                .as_ref()
                .ok_or(ResidentGd7WinnerAdoptionEvidenceRefusalChirho::InvalidRequestChirho)?;
            handoff_store_chirho
                .fetch_accepted_evidence_page_chirho(
                    manifest_chirho,
                    &requester_chirho.0,
                    grant_chirho,
                )
                .map(Box::new)
                .map(ResidentGd7WinnerAdoptionEvidenceReplyChirho::PageChirho)
                .map_err(Into::into)
        }
    }
}

fn require_accepted_attempt_digest_chirho(
    handoff_runtime_chirho: &ResidentGd7WinnerHandoffRuntimeChirho,
) -> Result<&str, ResidentGd7WinnerAdoptionEvidenceRefusalChirho> {
    handoff_runtime_chirho
        .accepted_attempt_digest_chirho()
        .ok_or(ResidentGd7WinnerAdoptionEvidenceRefusalChirho::AcceptedBarrierMissingChirho)
}

fn prepare_chirho(
    resident_chirho: &ResidentLedgerAuthorityChirho<'_>,
    handoff_store_chirho: &Gd7WinnerHandoffStoreChirho<'_>,
    state_chirho: &mut ResidentGd7WinnerAdoptionEvidenceStateChirho,
) -> Result<
    ResidentGd7WinnerAdoptionEvidenceInspectionChirho,
    ResidentGd7WinnerAdoptionEvidenceRefusalChirho,
> {
    if let Some(manifest_chirho) = &state_chirho.manifest_chirho {
        return Ok(
            ResidentGd7WinnerAdoptionEvidenceInspectionChirho::ReadyChirho(Box::new(
                manifest_chirho.clone(),
            )),
        );
    }
    let active_hint_chirho = handoff_store_chirho
        .load_current_chirho()?
        .ok_or(ResidentGd7WinnerAdoptionEvidenceRefusalChirho::AcceptedBarrierMissingChirho)?;
    let held_node_chirho = NodeIdChirho(
        active_hint_chirho
            .checkpoint_chirho
            .attempt_identity_chirho
            .held_transfer_identity_chirho
            .held_node_chirho
            .clone(),
    );
    let held_verifier_chirho = PinnedNodeGd7VerifierChirho::new_chirho(held_node_chirho)
        .map_err(|_| ResidentGd7WinnerAdoptionEvidenceRefusalChirho::InvalidRequestChirho)?;
    let (active_chirho, plan_checkpoint_chirho) =
        handoff_store_chirho.load_accepted_plan_chirho(&held_verifier_chirho)?;
    if state_chirho.attempt_digest_chirho.as_deref() != Some(&active_chirho.attempt_digest_chirho) {
        return Err(ResidentGd7WinnerAdoptionEvidenceRefusalChirho::AcceptedBarrierMissingChirho);
    }
    if state_chirho.history_root_chirho.is_none() {
        match resident_chirho.stage_next_accepted_gd7_winner_history_page_chirho(
            handoff_store_chirho,
            &active_chirho
                .checkpoint_chirho
                .attempt_identity_chirho
                .held_transfer_identity_chirho
                .reconciliation_checkpoint_ref_chirho,
            &plan_checkpoint_chirho,
            &held_verifier_chirho,
            state_chirho.history_restart_chirho.as_ref(),
        )? {
            Gd7WinnerHistoryStageOutcomeChirho::ContinueChirho { restart_chirho } => {
                state_chirho.history_restart_chirho = Some(restart_chirho);
                return Ok(
                    ResidentGd7WinnerAdoptionEvidenceInspectionChirho::AdvancedWinnerHistoryPageChirho,
                );
            }
            Gd7WinnerHistoryStageOutcomeChirho::CompleteChirho { root_chirho } => {
                state_chirho.history_restart_chirho = None;
                state_chirho.history_root_chirho = Some(*root_chirho);
            }
        }
    }
    let fork_baseline_root_chirho = resident_chirho.stage_accepted_gd7_fork_baseline_chirho(
        handoff_store_chirho,
        &active_chirho
            .checkpoint_chirho
            .attempt_identity_chirho
            .held_transfer_identity_chirho
            .reconciliation_checkpoint_ref_chirho,
        &plan_checkpoint_chirho,
        &held_verifier_chirho,
    )?;
    let transfer_identity_chirho = Gd7HeldEvidenceTransferIdentityChirho {
        reconciliation_identity_chirho: plan_checkpoint_chirho.identity_chirho,
        reconciliation_checkpoint_ref_chirho: active_chirho
            .checkpoint_chirho
            .attempt_identity_chirho
            .held_transfer_identity_chirho
            .reconciliation_checkpoint_ref_chirho
            .clone(),
        held_view_transfer_checkpoint_ref_chirho: active_chirho
            .checkpoint_chirho
            .attempt_identity_chirho
            .held_transfer_checkpoint_ref_chirho
            .clone(),
        winner_handoff_attempt_digest_chirho: active_chirho.attempt_digest_chirho,
    };
    let manifest_chirho = handoff_store_chirho.build_accepted_evidence_manifest_chirho(
        transfer_identity_chirho,
        state_chirho
            .history_root_chirho
            .as_ref()
            .expect("completed history staging retains its root"),
        &fork_baseline_root_chirho,
    )?;
    state_chirho.manifest_chirho = Some(manifest_chirho.clone());
    Ok(ResidentGd7WinnerAdoptionEvidenceInspectionChirho::ReadyChirho(Box::new(manifest_chirho)))
}

#[cfg(test)]
#[path = "winner_adoption_evidence_tests_chirho.rs"]
mod tests_chirho;
