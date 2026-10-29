// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Resident-actor ownership of the durable GD7 winner append-quiescence barrier.
//!
//! The handle exposes only bounded begin/status/abort operations. The held-side abort operation
//! cannot release an accepted barrier in this slice; no timer or restart releases it, and no
//! operation can adopt, compensate, move refs, or converge membership.

use super::winner_evidence_chirho::{
    reseal_resident_gd7_winner_current_view_during_handoff_chirho, ResidentGd7WinnerViewStateChirho,
};
use super::{
    ResidentEffectJournalCommandChirho, ResidentLedgerAuthorityChirho,
    ResidentLedgerAuthorityReadinessChirho, ResidentLedgerAuthorityRefusalChirho,
};
use crate::reconciliation_chirho::{
    gd7_winner_handoff_attempt_digest_chirho, ActiveGd7WinnerHandoffChirho,
    Gd7HeldViewTransferCheckpointChirho, Gd7HeldViewTransferIdentityChirho,
    Gd7HeldViewTransferStoreRefusalChirho, Gd7ReconciliationCheckpointChirho,
    Gd7ReconciliationStoreRefusalChirho, Gd7WinnerCurrentViewChallengeChirho,
    Gd7WinnerCurrentViewInspectionChirho, Gd7WinnerCurrentViewRefusalChirho,
    Gd7WinnerHandoffAttemptIdentityChirho, Gd7WinnerHandoffCommitOutcomeChirho,
    Gd7WinnerHandoffPhaseChirho, Gd7WinnerHandoffStoreChirho, Gd7WinnerHandoffStoreRefusalChirho,
    PinnedNodeGd7VerifierChirho,
};
use cairn_writer_elector_chirho::elector_port_chirho::NodeIdChirho;
use cairn_writer_elector_chirho::{
    LocalAppendAuthorityHandleChirho, LocalAppendAuthorityRefusalChirho,
    LocalAppendHandoffControlHandleChirho, LocalAppendHandoffGenerationGuardChirho,
    LocalAppendHandoffPreparationChirho, LocalAppendHandoffReadGenerationChirho,
};
use cairn_writer_head_chirho::writer_head_chirho::consistency_group_digest_chirho;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt;
use std::sync::mpsc::{sync_channel, SyncSender, TrySendError};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResidentGd7WinnerHandoffStatusChirho {
    pub attempt_digest_chirho: String,
    pub checkpoint_ref_chirho: String,
    pub attempt_identity_chirho: Gd7WinnerHandoffAttemptIdentityChirho,
    pub phase_chirho: Gd7WinnerHandoffPhaseChirho,
    pub inspection_chirho: Gd7WinnerCurrentViewInspectionChirho,
    pub preparing_process_generation_chirho: u64,
    pub accepting_process_generation_chirho: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants must carry the Chirho suffix"
)]
pub enum ResidentGd7WinnerHandoffRefusalChirho {
    MailboxFullChirho,
    ActorUnavailableChirho,
    NoAttemptChirho,
    InvalidRequestChirho,
    DurableHeadChangedChirho,
    MigrationSourceFenceActiveChirho,
    WinnerStateChangedChirho,
    /// The guard presented does not name the active attempt. Pre-traversal; nothing was read.
    HistoricalCutAttemptMismatchChirho,
    /// The resident could not be probed under the handoff guard. Pre-traversal; nothing was read.
    HistoricalCutProbeFailedChirho,
    /// The readiness SNAPSHOT failed its floors — identity, node, term, genesis, or evidence cut.
    /// Distinct from every tail/extension cause below: this fires before the tail is even considered.
    HistoricalCutSnapshotRefusedChirho,
    /// The post-cut extension was not verifiable as compensation-class reaching the cut anchor.
    ///
    /// NOT "this reconciliation's lawful compensation", which this refusal used to claim: root
    /// scoping across the fork is structurally unenforceable here, and coordinate validity is
    /// privacy-gated and unbuilt. See `verify_post_cut_extension_class_and_anchor_chirho`.
    ///
    /// Carries the traversal's own typed detail rather than collapsing it, because an arm that can
    /// only assert "something refused" cannot tell WHICH property refused — and a change that breaks
    /// one property while tripping another leaves such an arm green while the property it exists to
    /// pin is gone. That is the tamper-fixture failure in assertion form, and this repo has already
    /// had one (`verified_balances_reject_tampered_rows_chirho` refusing on a signature while its
    /// fixture summed to zero). The detail distinguishes at least: anchor/tail digest mismatch,
    /// a wrong-CLASS record, and a traversal that never reached the anchor. It does NOT distinguish
    /// a foreign-reconciliation record: nothing here can tell one, by construction.
    HistoricalCutExtensionRefusedChirho {
        detail_chirho: String,
    },
    DurabilityUnconfirmedChirho,
    LocalAuthorityChirho(LocalAppendAuthorityRefusalChirho),
    HeldCheckpointChirho(Gd7HeldViewTransferStoreRefusalChirho),
    ReconciliationCheckpointChirho(Gd7ReconciliationStoreRefusalChirho),
    CurrentViewChirho(Gd7WinnerCurrentViewRefusalChirho),
    StoreChirho(Gd7WinnerHandoffStoreRefusalChirho),
}

impl fmt::Display for ResidentGd7WinnerHandoffRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MailboxFullChirho => {
                formatter_chirho.write_str("resident winner-handoff mailbox is at capacity")
            }
            Self::ActorUnavailableChirho => {
                formatter_chirho.write_str("resident winner-handoff actor is unavailable")
            }
            Self::NoAttemptChirho => {
                formatter_chirho.write_str("resident winner-handoff has no durable attempt")
            }
            Self::InvalidRequestChirho => {
                formatter_chirho.write_str("resident winner-handoff request is invalid")
            }
            Self::DurableHeadChangedChirho => formatter_chirho
                .write_str("resident winner-handoff durable head changed during startup"),
            Self::MigrationSourceFenceActiveChirho => formatter_chirho
                .write_str("tenant migration source fence owns the resident append barrier"),
            Self::WinnerStateChangedChirho => {
                formatter_chirho.write_str("resident winner state differs from the sealed handoff")
            }
            Self::HistoricalCutAttemptMismatchChirho => formatter_chirho
                .write_str("historical cut guard names a different winner-handoff attempt"),
            Self::HistoricalCutProbeFailedChirho => formatter_chirho
                .write_str("historical cut could not probe the resident under its handoff guard"),
            Self::HistoricalCutSnapshotRefusedChirho => formatter_chirho
                .write_str("historical cut readiness snapshot failed its identity or floor checks"),
            Self::HistoricalCutExtensionRefusedChirho { detail_chirho } => {
                write!(
                    formatter_chirho,
                    "historical cut post-cut extension refused: {detail_chirho}"
                )
            }
            Self::DurabilityUnconfirmedChirho => formatter_chirho.write_str(
                "resident winner-handoff head durability is unconfirmed; appends remain frozen",
            ),
            Self::LocalAuthorityChirho(error_chirho) => {
                write!(
                    formatter_chirho,
                    "winner-handoff authority refused: {error_chirho}"
                )
            }
            Self::HeldCheckpointChirho(error_chirho) => {
                write!(
                    formatter_chirho,
                    "winner-handoff held checkpoint refused: {error_chirho}"
                )
            }
            Self::ReconciliationCheckpointChirho(error_chirho) => {
                write!(
                    formatter_chirho,
                    "winner-handoff reconciliation checkpoint refused: {error_chirho}"
                )
            }
            Self::CurrentViewChirho(error_chirho) => {
                write!(
                    formatter_chirho,
                    "winner-handoff current view refused: {error_chirho}"
                )
            }
            Self::StoreChirho(error_chirho) => {
                write!(
                    formatter_chirho,
                    "winner-handoff store refused: {error_chirho}"
                )
            }
        }
    }
}

impl Error for ResidentGd7WinnerHandoffRefusalChirho {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::LocalAuthorityChirho(error_chirho) => Some(error_chirho),
            Self::HeldCheckpointChirho(error_chirho) => Some(error_chirho),
            Self::ReconciliationCheckpointChirho(error_chirho) => Some(error_chirho),
            Self::CurrentViewChirho(error_chirho) => Some(error_chirho),
            Self::StoreChirho(error_chirho) => Some(error_chirho),
            Self::HistoricalCutAttemptMismatchChirho
            | Self::HistoricalCutProbeFailedChirho
            | Self::HistoricalCutSnapshotRefusedChirho
            | Self::HistoricalCutExtensionRefusedChirho { .. }
            | Self::MailboxFullChirho
            | Self::ActorUnavailableChirho
            | Self::NoAttemptChirho
            | Self::InvalidRequestChirho
            | Self::DurableHeadChangedChirho
            | Self::MigrationSourceFenceActiveChirho
            | Self::WinnerStateChangedChirho
            | Self::DurabilityUnconfirmedChirho => None,
        }
    }
}

#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants must carry the Chirho suffix"
)]
pub(super) enum ResidentGd7WinnerHandoffCommandChirho {
    CurrentChirho,
    BeginChirho(Box<ResidentGd7WinnerHandoffBeginRequestChirho>),
    StatusChirho { attempt_digest_chirho: String },
    AbortChirho { attempt_digest_chirho: String },
}

pub(super) struct ResidentGd7WinnerHandoffBeginRequestChirho {
    held_transfer_identity_chirho: Gd7HeldViewTransferIdentityChirho,
    reconciliation_checkpoint_chirho: Box<Gd7ReconciliationCheckpointChirho>,
    held_transfer_checkpoint_ref_chirho: String,
    held_transfer_checkpoint_chirho: Box<Gd7HeldViewTransferCheckpointChirho>,
    expected_bundle_root_object_digest_chirho: String,
    challenge_chirho: Gd7WinnerCurrentViewChallengeChirho,
}

/// Restricted facade for one actor-owned winner handoff barrier.
#[derive(Clone)]
pub struct ResidentGd7WinnerHandoffHandleChirho {
    pub(super) command_sender_chirho: SyncSender<ResidentEffectJournalCommandChirho>,
}

impl ResidentGd7WinnerHandoffHandleChirho {
    pub fn current_chirho(
        &self,
    ) -> Result<Option<ResidentGd7WinnerHandoffStatusChirho>, ResidentGd7WinnerHandoffRefusalChirho>
    {
        match self.request_chirho(ResidentGd7WinnerHandoffCommandChirho::CurrentChirho) {
            Ok(status_chirho) => Ok(Some(status_chirho)),
            Err(ResidentGd7WinnerHandoffRefusalChirho::NoAttemptChirho) => Ok(None),
            Err(error_chirho) => Err(error_chirho),
        }
    }

    pub fn begin_chirho(
        &self,
        held_transfer_identity_chirho: Gd7HeldViewTransferIdentityChirho,
        reconciliation_checkpoint_chirho: Box<Gd7ReconciliationCheckpointChirho>,
        held_transfer_checkpoint_ref_chirho: String,
        held_transfer_checkpoint_chirho: Box<Gd7HeldViewTransferCheckpointChirho>,
        expected_bundle_root_object_digest_chirho: String,
        challenge_chirho: Gd7WinnerCurrentViewChallengeChirho,
    ) -> Result<ResidentGd7WinnerHandoffStatusChirho, ResidentGd7WinnerHandoffRefusalChirho> {
        self.request_chirho(ResidentGd7WinnerHandoffCommandChirho::BeginChirho(
            Box::new(ResidentGd7WinnerHandoffBeginRequestChirho {
                held_transfer_identity_chirho,
                reconciliation_checkpoint_chirho,
                held_transfer_checkpoint_ref_chirho,
                held_transfer_checkpoint_chirho,
                expected_bundle_root_object_digest_chirho,
                challenge_chirho,
            }),
        ))
    }

    pub fn status_chirho(
        &self,
        attempt_digest_chirho: String,
    ) -> Result<ResidentGd7WinnerHandoffStatusChirho, ResidentGd7WinnerHandoffRefusalChirho> {
        self.request_chirho(ResidentGd7WinnerHandoffCommandChirho::StatusChirho {
            attempt_digest_chirho,
        })
    }

    pub fn abort_chirho(
        &self,
        attempt_digest_chirho: String,
    ) -> Result<ResidentGd7WinnerHandoffStatusChirho, ResidentGd7WinnerHandoffRefusalChirho> {
        self.request_chirho(ResidentGd7WinnerHandoffCommandChirho::AbortChirho {
            attempt_digest_chirho,
        })
    }

    fn request_chirho(
        &self,
        command_chirho: ResidentGd7WinnerHandoffCommandChirho,
    ) -> Result<ResidentGd7WinnerHandoffStatusChirho, ResidentGd7WinnerHandoffRefusalChirho> {
        let (reply_sender_chirho, reply_receiver_chirho) = sync_channel(1);
        self.command_sender_chirho
            .try_send(ResidentEffectJournalCommandChirho::Gd7WinnerHandoffChirho {
                command_chirho,
                reply_chirho: reply_sender_chirho,
            })
            .map_err(|error_chirho| match error_chirho {
                TrySendError::Full(_command_chirho) => {
                    ResidentGd7WinnerHandoffRefusalChirho::MailboxFullChirho
                }
                TrySendError::Disconnected(_command_chirho) => {
                    ResidentGd7WinnerHandoffRefusalChirho::ActorUnavailableChirho
                }
            })?;
        reply_receiver_chirho.recv().map_err(|_error_chirho| {
            ResidentGd7WinnerHandoffRefusalChirho::ActorUnavailableChirho
        })?
    }
}

#[derive(Default)]
pub(super) struct ResidentGd7WinnerHandoffRuntimeChirho {
    current_chirho: Option<ActiveGd7WinnerHandoffChirho>,
    durability_unconfirmed_chirho: bool,
}

impl ResidentGd7WinnerHandoffRuntimeChirho {
    #[cfg(test)]
    pub(super) fn from_durable_active_test_fixture_chirho(
        active_chirho: ActiveGd7WinnerHandoffChirho,
    ) -> Self {
        Self {
            current_chirho: Some(active_chirho),
            durability_unconfirmed_chirho: false,
        }
    }

    pub(super) fn restore_chirho(
        store_chirho: &Gd7WinnerHandoffStoreChirho<'_>,
        control_chirho: &LocalAppendHandoffControlHandleChirho,
        resident_chirho: &ResidentLedgerAuthorityChirho<'_>,
        inspected_chirho: Option<ActiveGd7WinnerHandoffChirho>,
    ) -> Result<Self, ResidentGd7WinnerHandoffRefusalChirho> {
        let reloaded_chirho = store_chirho
            .load_current_chirho()
            .map_err(ResidentGd7WinnerHandoffRefusalChirho::StoreChirho)?;
        if reloaded_chirho != inspected_chirho {
            return Err(ResidentGd7WinnerHandoffRefusalChirho::DurableHeadChangedChirho);
        }
        let mut runtime_chirho = Self {
            current_chirho: inspected_chirho,
            durability_unconfirmed_chirho: false,
        };
        let Some(current_chirho) = runtime_chirho.current_chirho.clone() else {
            return Ok(runtime_chirho);
        };
        match current_chirho.checkpoint_chirho.phase_chirho {
            Gd7WinnerHandoffPhaseChirho::PreparingChirho
            | Gd7WinnerHandoffPhaseChirho::AcceptedChirho => {
                // Active or ambiguous owners still fail toward more freeze: restore their exact
                // marker before re-fsyncing the signed head, then verify under that same owner.
                control_chirho
                    .restore_handoff_chirho(&current_chirho.attempt_digest_chirho)
                    .map_err(ResidentGd7WinnerHandoffRefusalChirho::LocalAuthorityChirho)?;
                confirm_active_chirho(store_chirho, &mut runtime_chirho, &current_chirho)?;
                let observed_chirho = control_chirho
                    .handoff_read_handle_chirho()
                    .try_acquire_handoff_read_chirho(&current_chirho.attempt_digest_chirho)
                    .map_err(ResidentGd7WinnerHandoffRefusalChirho::LocalAuthorityChirho)?;
                let guard_chirho = control_chirho
                    .try_acquire_observed_handoff_chirho(&observed_chirho)
                    .map_err(ResidentGd7WinnerHandoffRefusalChirho::LocalAuthorityChirho)?;
                let _readiness_chirho =
                    verify_historical_cut_chirho(resident_chirho, &guard_chirho, &current_chirho)?;
            }
            Gd7WinnerHandoffPhaseChirho::AbortedChirho => {
                // A terminal head confirms without claiming. It releases only an exact marker it
                // first observed as its own, leaving a later migration/GD7 owner untouched.
                confirm_active_chirho(store_chirho, &mut runtime_chirho, &current_chirho)?;
                control_chirho
                    .release_if_observed_owner_chirho(&current_chirho.attempt_digest_chirho)
                    .map_err(ResidentGd7WinnerHandoffRefusalChirho::LocalAuthorityChirho)?;
            }
        }
        Ok(runtime_chirho)
    }

    pub(super) fn blocks_mutations_chirho(&self) -> bool {
        self.durability_unconfirmed_chirho
            || self.current_chirho.as_ref().is_some_and(|current_chirho| {
                current_chirho.checkpoint_chirho.phase_chirho
                    != Gd7WinnerHandoffPhaseChirho::AbortedChirho
            })
    }

    pub(super) fn accepted_attempt_digest_chirho(&self) -> Option<&str> {
        if self.durability_unconfirmed_chirho {
            return None;
        }
        self.current_chirho.as_ref().and_then(|current_chirho| {
            (current_chirho.checkpoint_chirho.phase_chirho
                == Gd7WinnerHandoffPhaseChirho::AcceptedChirho)
                .then_some(current_chirho.attempt_digest_chirho.as_str())
        })
    }

    pub(super) fn read_resident_chirho<OutputChirho>(
        &self,
        resident_chirho: &ResidentLedgerAuthorityChirho<'_>,
        local_authority_chirho: &LocalAppendAuthorityHandleChirho,
        read_chirho: impl FnOnce(
            &ResidentLedgerAuthorityChirho<'_>,
            Option<&LocalAppendHandoffReadGenerationChirho>,
        ) -> Result<OutputChirho, ResidentLedgerAuthorityRefusalChirho>,
    ) -> Result<OutputChirho, ResidentLedgerAuthorityRefusalChirho> {
        let Some(active_chirho) = self
            .current_chirho
            .as_ref()
            .filter(|_active_chirho| self.blocks_mutations_chirho())
        else {
            return read_chirho(resident_chirho, None);
        };
        // This snapshot witness releases the authority mutex before the read. No append API accepts
        // its distinct type; mutation paths acquire normal authority and still see HandoffActive.
        let handoff_read_chirho = local_authority_chirho
            .try_acquire_handoff_read_chirho(&active_chirho.attempt_digest_chirho)
            .map_err(|reason_chirho| {
                ResidentLedgerAuthorityRefusalChirho::LocalGenerationRefusedChirho { reason_chirho }
            })?;
        read_chirho(resident_chirho, Some(&handoff_read_chirho))
    }
}

fn confirm_active_chirho(
    store_chirho: &Gd7WinnerHandoffStoreChirho<'_>,
    runtime_chirho: &mut ResidentGd7WinnerHandoffRuntimeChirho,
    current_chirho: &ActiveGd7WinnerHandoffChirho,
) -> Result<(), ResidentGd7WinnerHandoffRefusalChirho> {
    let confirmation_chirho = store_chirho
        .confirm_active_chirho(current_chirho)
        .map_err(ResidentGd7WinnerHandoffRefusalChirho::StoreChirho)?;
    let (_committed_chirho, durable_chirho) = confirmation_chirho.into_parts_chirho();
    if !durable_chirho {
        runtime_chirho.durability_unconfirmed_chirho = true;
        return Err(ResidentGd7WinnerHandoffRefusalChirho::DurabilityUnconfirmedChirho);
    }
    Ok(())
}

pub(super) fn handle_resident_gd7_winner_handoff_chirho(
    command_chirho: ResidentGd7WinnerHandoffCommandChirho,
    resident_chirho: &ResidentLedgerAuthorityChirho<'_>,
    winner_view_state_chirho: &mut ResidentGd7WinnerViewStateChirho,
    runtime_chirho: &mut ResidentGd7WinnerHandoffRuntimeChirho,
    store_chirho: &Gd7WinnerHandoffStoreChirho<'_>,
    local_authority_chirho: &LocalAppendAuthorityHandleChirho,
) -> Result<ResidentGd7WinnerHandoffStatusChirho, ResidentGd7WinnerHandoffRefusalChirho> {
    reconcile_unconfirmed_chirho(runtime_chirho, store_chirho, local_authority_chirho)?;
    match command_chirho {
        ResidentGd7WinnerHandoffCommandChirho::CurrentChirho => {
            let current_chirho = store_chirho
                .load_current_chirho()
                .map_err(ResidentGd7WinnerHandoffRefusalChirho::StoreChirho)?
                .ok_or(ResidentGd7WinnerHandoffRefusalChirho::NoAttemptChirho)?;
            runtime_chirho.current_chirho = Some(current_chirho.clone());
            Ok(status_from_active_chirho(&current_chirho))
        }
        ResidentGd7WinnerHandoffCommandChirho::BeginChirho(request_chirho) => begin_chirho(
            resident_chirho,
            winner_view_state_chirho,
            runtime_chirho,
            store_chirho,
            local_authority_chirho,
            request_chirho.held_transfer_identity_chirho,
            request_chirho.reconciliation_checkpoint_chirho,
            request_chirho.held_transfer_checkpoint_ref_chirho,
            request_chirho.held_transfer_checkpoint_chirho,
            request_chirho.expected_bundle_root_object_digest_chirho,
            request_chirho.challenge_chirho,
        ),
        ResidentGd7WinnerHandoffCommandChirho::StatusChirho {
            attempt_digest_chirho,
        } => current_status_chirho(store_chirho, runtime_chirho, &attempt_digest_chirho),
        ResidentGd7WinnerHandoffCommandChirho::AbortChirho {
            attempt_digest_chirho,
        } => abort_chirho(
            resident_chirho,
            runtime_chirho,
            store_chirho,
            local_authority_chirho,
            &attempt_digest_chirho,
        ),
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "the actor binds one exact held identity, challenge, resident and durable store"
)]
fn begin_chirho(
    resident_chirho: &ResidentLedgerAuthorityChirho<'_>,
    winner_view_state_chirho: &mut ResidentGd7WinnerViewStateChirho,
    runtime_chirho: &mut ResidentGd7WinnerHandoffRuntimeChirho,
    store_chirho: &Gd7WinnerHandoffStoreChirho<'_>,
    local_authority_chirho: &LocalAppendAuthorityHandleChirho,
    held_transfer_identity_chirho: Gd7HeldViewTransferIdentityChirho,
    reconciliation_checkpoint_chirho: Box<Gd7ReconciliationCheckpointChirho>,
    held_transfer_checkpoint_ref_chirho: String,
    held_transfer_checkpoint_chirho: Box<Gd7HeldViewTransferCheckpointChirho>,
    expected_bundle_root_object_digest_chirho: String,
    challenge_chirho: Gd7WinnerCurrentViewChallengeChirho,
) -> Result<ResidentGd7WinnerHandoffStatusChirho, ResidentGd7WinnerHandoffRefusalChirho> {
    let held_verifier_chirho = PinnedNodeGd7VerifierChirho::new_chirho(NodeIdChirho(
        held_transfer_identity_chirho.held_node_chirho.clone(),
    ))
    .map_err(|_error_chirho| ResidentGd7WinnerHandoffRefusalChirho::InvalidRequestChirho)?;
    store_chirho
        .verify_complete_held_checkpoint_chirho(
            &held_transfer_checkpoint_ref_chirho,
            &held_transfer_checkpoint_chirho,
            &held_transfer_identity_chirho,
            &expected_bundle_root_object_digest_chirho,
            &held_verifier_chirho,
        )
        .map_err(ResidentGd7WinnerHandoffRefusalChirho::HeldCheckpointChirho)?;
    let expected_winner_genesis_digest_chirho = held_transfer_checkpoint_chirho
        .inspection_chirho
        .as_ref()
        .ok_or(ResidentGd7WinnerHandoffRefusalChirho::InvalidRequestChirho)?
        .bundle_root_chirho
        .winner_journal_genesis_digest_chirho
        .clone();
    let canonical_challenge_bytes_chirho = challenge_chirho
        .canonical_bytes_chirho()
        .map_err(ResidentGd7WinnerHandoffRefusalChirho::CurrentViewChirho)?;
    let attempt_identity_chirho = Gd7WinnerHandoffAttemptIdentityChirho {
        held_transfer_identity_chirho,
        held_transfer_checkpoint_ref_chirho,
        expected_bundle_root_object_digest_chirho,
        challenge_digest_chirho: challenge_chirho
            .digest_chirho()
            .map_err(ResidentGd7WinnerHandoffRefusalChirho::CurrentViewChirho)?,
    };
    let attempt_digest_chirho = gd7_winner_handoff_attempt_digest_chirho(&attempt_identity_chirho)
        .map_err(ResidentGd7WinnerHandoffRefusalChirho::StoreChirho)?;
    let current_chirho = store_chirho
        .load_current_chirho()
        .map_err(ResidentGd7WinnerHandoffRefusalChirho::StoreChirho)?;
    if let Some(current_chirho) = current_chirho.as_ref() {
        if current_chirho.attempt_digest_chirho != attempt_digest_chirho
            && current_chirho.checkpoint_chirho.phase_chirho
                != Gd7WinnerHandoffPhaseChirho::AbortedChirho
        {
            return Err(ResidentGd7WinnerHandoffRefusalChirho::StoreChirho(
                Gd7WinnerHandoffStoreRefusalChirho::ActiveAttemptMismatchChirho,
            ));
        }
    }
    store_chirho
        .verify_and_retain_plan_sealed_checkpoint_chirho(
            &attempt_identity_chirho
                .held_transfer_identity_chirho
                .reconciliation_checkpoint_ref_chirho,
            &reconciliation_checkpoint_chirho,
            &attempt_identity_chirho.held_transfer_identity_chirho,
            &expected_winner_genesis_digest_chirho,
            &held_verifier_chirho,
        )
        .map_err(ResidentGd7WinnerHandoffRefusalChirho::ReconciliationCheckpointChirho)?;
    if let Some(current_chirho) = current_chirho {
        if current_chirho.attempt_digest_chirho == attempt_digest_chirho {
            runtime_chirho.current_chirho = Some(current_chirho.clone());
            return match current_chirho.checkpoint_chirho.phase_chirho {
                Gd7WinnerHandoffPhaseChirho::PreparingChirho => resume_preparing_chirho(
                    resident_chirho,
                    runtime_chirho,
                    store_chirho,
                    local_authority_chirho,
                    current_chirho,
                ),
                Gd7WinnerHandoffPhaseChirho::AcceptedChirho => {
                    local_authority_chirho
                        .restore_handoff_chirho(&attempt_digest_chirho)
                        .map_err(ResidentGd7WinnerHandoffRefusalChirho::LocalAuthorityChirho)?;
                    Ok(status_from_active_chirho(&current_chirho))
                }
                Gd7WinnerHandoffPhaseChirho::AbortedChirho => {
                    Err(ResidentGd7WinnerHandoffRefusalChirho::StoreChirho(
                        Gd7WinnerHandoffStoreRefusalChirho::InvalidTransitionChirho,
                    ))
                }
            };
        }
    }

    let preparation_chirho = local_authority_chirho
        .try_prepare_handoff_chirho(&attempt_digest_chirho)
        .map_err(ResidentGd7WinnerHandoffRefusalChirho::LocalAuthorityChirho)?;
    let inspection_chirho = reseal_resident_gd7_winner_current_view_during_handoff_chirho(
        resident_chirho,
        winner_view_state_chirho,
        &preparation_chirho,
        challenge_chirho,
    )
    .map_err(ResidentGd7WinnerHandoffRefusalChirho::CurrentViewChirho)?;
    let preparing_outcome_chirho = store_chirho
        .commit_preparing_chirho(
            attempt_identity_chirho,
            &canonical_challenge_bytes_chirho,
            inspection_chirho,
            preparation_chirho.process_generation_chirho(),
        )
        .map_err(ResidentGd7WinnerHandoffRefusalChirho::StoreChirho)?;
    let (active_preparing_chirho, handoff_guard_chirho) = apply_preparing_commit_outcome_chirho(
        runtime_chirho,
        preparation_chirho,
        preparing_outcome_chirho,
    )?;
    let _readiness_chirho = verify_original_term_activation_chirho(
        resident_chirho,
        &handoff_guard_chirho,
        &active_preparing_chirho,
    )?;
    let accepted_outcome_chirho = store_chirho
        .commit_accepted_chirho(
            &active_preparing_chirho.attempt_digest_chirho,
            &active_preparing_chirho.checkpoint_ref_chirho,
            handoff_guard_chirho.process_generation_chirho(),
        )
        .map_err(ResidentGd7WinnerHandoffRefusalChirho::StoreChirho)?;
    let (accepted_chirho, accepted_durable_chirho) = accepted_outcome_chirho.into_parts_chirho();
    let active_accepted_chirho = active_from_committed_chirho(accepted_chirho);
    runtime_chirho.current_chirho = Some(active_accepted_chirho.clone());
    runtime_chirho.durability_unconfirmed_chirho = !accepted_durable_chirho;
    if !accepted_durable_chirho {
        return Err(ResidentGd7WinnerHandoffRefusalChirho::DurabilityUnconfirmedChirho);
    }
    Ok(status_from_active_chirho(&active_accepted_chirho))
}

fn resume_preparing_chirho(
    resident_chirho: &ResidentLedgerAuthorityChirho<'_>,
    runtime_chirho: &mut ResidentGd7WinnerHandoffRuntimeChirho,
    store_chirho: &Gd7WinnerHandoffStoreChirho<'_>,
    local_authority_chirho: &LocalAppendAuthorityHandleChirho,
    preparing_chirho: ActiveGd7WinnerHandoffChirho,
) -> Result<ResidentGd7WinnerHandoffStatusChirho, ResidentGd7WinnerHandoffRefusalChirho> {
    local_authority_chirho
        .restore_handoff_chirho(&preparing_chirho.attempt_digest_chirho)
        .map_err(ResidentGd7WinnerHandoffRefusalChirho::LocalAuthorityChirho)?;
    let guard_chirho = local_authority_chirho
        .try_acquire_handoff_chirho(&preparing_chirho.attempt_digest_chirho)
        .map_err(ResidentGd7WinnerHandoffRefusalChirho::LocalAuthorityChirho)?;
    let _readiness_chirho =
        verify_original_term_activation_chirho(resident_chirho, &guard_chirho, &preparing_chirho)?;
    let accepted_outcome_chirho = store_chirho
        .commit_accepted_chirho(
            &preparing_chirho.attempt_digest_chirho,
            &preparing_chirho.checkpoint_ref_chirho,
            guard_chirho.process_generation_chirho(),
        )
        .map_err(ResidentGd7WinnerHandoffRefusalChirho::StoreChirho)?;
    let (accepted_chirho, accepted_durable_chirho) = accepted_outcome_chirho.into_parts_chirho();
    let active_chirho = active_from_committed_chirho(accepted_chirho);
    runtime_chirho.current_chirho = Some(active_chirho.clone());
    runtime_chirho.durability_unconfirmed_chirho = !accepted_durable_chirho;
    if !accepted_durable_chirho {
        return Err(ResidentGd7WinnerHandoffRefusalChirho::DurabilityUnconfirmedChirho);
    }
    Ok(status_from_active_chirho(&active_chirho))
}

fn abort_chirho(
    resident_chirho: &ResidentLedgerAuthorityChirho<'_>,
    runtime_chirho: &mut ResidentGd7WinnerHandoffRuntimeChirho,
    store_chirho: &Gd7WinnerHandoffStoreChirho<'_>,
    local_authority_chirho: &LocalAppendAuthorityHandleChirho,
    attempt_digest_chirho: &str,
) -> Result<ResidentGd7WinnerHandoffStatusChirho, ResidentGd7WinnerHandoffRefusalChirho> {
    let current_chirho = exact_current_chirho(store_chirho, attempt_digest_chirho)?;
    match current_chirho.checkpoint_chirho.phase_chirho {
        Gd7WinnerHandoffPhaseChirho::AbortedChirho => {
            runtime_chirho.current_chirho = Some(current_chirho.clone());
            return Ok(status_from_active_chirho(&current_chirho));
        }
        Gd7WinnerHandoffPhaseChirho::AcceptedChirho => {
            return Err(ResidentGd7WinnerHandoffRefusalChirho::StoreChirho(
                Gd7WinnerHandoffStoreRefusalChirho::InvalidTransitionChirho,
            ));
        }
        Gd7WinnerHandoffPhaseChirho::PreparingChirho => {}
    }
    let guard_chirho = local_authority_chirho
        .try_acquire_handoff_chirho(attempt_digest_chirho)
        .map_err(ResidentGd7WinnerHandoffRefusalChirho::LocalAuthorityChirho)?;
    let _readiness_chirho =
        verify_historical_cut_chirho(resident_chirho, &guard_chirho, &current_chirho)?;
    let aborted_outcome_chirho = store_chirho
        .commit_aborted_chirho(attempt_digest_chirho, &current_chirho.checkpoint_ref_chirho)
        .map_err(ResidentGd7WinnerHandoffRefusalChirho::StoreChirho)?;
    let active_chirho =
        apply_aborted_commit_outcome_chirho(runtime_chirho, guard_chirho, aborted_outcome_chirho)?;
    Ok(status_from_active_chirho(&active_chirho))
}

fn apply_preparing_commit_outcome_chirho<'authority_chirho>(
    runtime_chirho: &mut ResidentGd7WinnerHandoffRuntimeChirho,
    preparation_chirho: LocalAppendHandoffPreparationChirho<'authority_chirho>,
    outcome_chirho: Gd7WinnerHandoffCommitOutcomeChirho,
) -> Result<
    (
        ActiveGd7WinnerHandoffChirho,
        LocalAppendHandoffGenerationGuardChirho<'authority_chirho>,
    ),
    ResidentGd7WinnerHandoffRefusalChirho,
> {
    // The marker activates while the authority mutex is still held. Only then may an ambiguous
    // fixed-head result return to the actor, so durable-frozen can never pair with live-unfrozen.
    let handoff_guard_chirho = preparation_chirho.activate_chirho();
    let (preparing_chirho, preparing_durable_chirho) = outcome_chirho.into_parts_chirho();
    let active_chirho = active_from_committed_chirho(preparing_chirho);
    runtime_chirho.current_chirho = Some(active_chirho.clone());
    runtime_chirho.durability_unconfirmed_chirho = !preparing_durable_chirho;
    if !preparing_durable_chirho {
        return Err(ResidentGd7WinnerHandoffRefusalChirho::DurabilityUnconfirmedChirho);
    }
    Ok((active_chirho, handoff_guard_chirho))
}

fn apply_aborted_commit_outcome_chirho(
    runtime_chirho: &mut ResidentGd7WinnerHandoffRuntimeChirho,
    handoff_guard_chirho: LocalAppendHandoffGenerationGuardChirho<'_>,
    outcome_chirho: Gd7WinnerHandoffCommitOutcomeChirho,
) -> Result<ActiveGd7WinnerHandoffChirho, ResidentGd7WinnerHandoffRefusalChirho> {
    let (aborted_chirho, aborted_durable_chirho) = outcome_chirho.into_parts_chirho();
    let active_chirho = active_from_committed_chirho(aborted_chirho);
    runtime_chirho.current_chirho = Some(active_chirho.clone());
    runtime_chirho.durability_unconfirmed_chirho = !aborted_durable_chirho;
    if !aborted_durable_chirho {
        return Err(ResidentGd7WinnerHandoffRefusalChirho::DurabilityUnconfirmedChirho);
    }
    // Release is deliberately after durable confirmation. Dropping the guard on an ambiguous
    // result retains the marker; only this confirmed branch clears it.
    handoff_guard_chirho.release_chirho();
    Ok(active_chirho)
}

fn reconcile_unconfirmed_chirho(
    runtime_chirho: &mut ResidentGd7WinnerHandoffRuntimeChirho,
    store_chirho: &Gd7WinnerHandoffStoreChirho<'_>,
    local_authority_chirho: &LocalAppendAuthorityHandleChirho,
) -> Result<(), ResidentGd7WinnerHandoffRefusalChirho> {
    if !runtime_chirho.durability_unconfirmed_chirho {
        return Ok(());
    }
    let active_chirho = runtime_chirho
        .current_chirho
        .as_ref()
        .ok_or(ResidentGd7WinnerHandoffRefusalChirho::InvalidRequestChirho)?;
    let outcome_chirho = store_chirho
        .confirm_active_chirho(active_chirho)
        .map_err(ResidentGd7WinnerHandoffRefusalChirho::StoreChirho)?;
    let (_committed_chirho, durable_chirho) = outcome_chirho.into_parts_chirho();
    if !durable_chirho {
        return Err(ResidentGd7WinnerHandoffRefusalChirho::DurabilityUnconfirmedChirho);
    }
    runtime_chirho.durability_unconfirmed_chirho = false;
    if active_chirho.checkpoint_chirho.phase_chirho == Gd7WinnerHandoffPhaseChirho::AbortedChirho {
        local_authority_chirho
            .try_acquire_handoff_chirho(&active_chirho.attempt_digest_chirho)
            .map_err(ResidentGd7WinnerHandoffRefusalChirho::LocalAuthorityChirho)?
            .release_chirho();
    }
    Ok(())
}

fn current_status_chirho(
    store_chirho: &Gd7WinnerHandoffStoreChirho<'_>,
    runtime_chirho: &mut ResidentGd7WinnerHandoffRuntimeChirho,
    attempt_digest_chirho: &str,
) -> Result<ResidentGd7WinnerHandoffStatusChirho, ResidentGd7WinnerHandoffRefusalChirho> {
    let current_chirho = exact_current_chirho(store_chirho, attempt_digest_chirho)?;
    runtime_chirho.current_chirho = Some(current_chirho.clone());
    Ok(status_from_active_chirho(&current_chirho))
}

fn exact_current_chirho(
    store_chirho: &Gd7WinnerHandoffStoreChirho<'_>,
    attempt_digest_chirho: &str,
) -> Result<ActiveGd7WinnerHandoffChirho, ResidentGd7WinnerHandoffRefusalChirho> {
    let current_chirho = store_chirho
        .load_current_chirho()
        .map_err(ResidentGd7WinnerHandoffRefusalChirho::StoreChirho)?
        .ok_or(ResidentGd7WinnerHandoffRefusalChirho::InvalidRequestChirho)?;
    if current_chirho.attempt_digest_chirho != attempt_digest_chirho {
        return Err(ResidentGd7WinnerHandoffRefusalChirho::StoreChirho(
            Gd7WinnerHandoffStoreRefusalChirho::ActiveAttemptMismatchChirho,
        ));
    }
    Ok(current_chirho)
}

fn verify_original_term_activation_chirho(
    resident_chirho: &ResidentLedgerAuthorityChirho<'_>,
    guard_chirho: &LocalAppendHandoffGenerationGuardChirho<'_>,
    current_chirho: &ActiveGd7WinnerHandoffChirho,
) -> Result<ResidentLedgerAuthorityReadinessChirho, ResidentGd7WinnerHandoffRefusalChirho> {
    let readiness_chirho =
        verify_historical_cut_chirho(resident_chirho, guard_chirho, current_chirho)?;
    let original_term_chirho = current_chirho
        .checkpoint_chirho
        .attempt_identity_chirho
        .held_transfer_identity_chirho
        .winner_term_chirho;
    if readiness_chirho.published_raft_term_chirho != original_term_chirho {
        return Err(ResidentGd7WinnerHandoffRefusalChirho::WinnerStateChangedChirho);
    }
    Ok(readiness_chirho)
}

/// THE OWNER OF HISTORICAL-CUT STRICTNESS. Restoration is safe because of what happens HERE.
///
/// WHY THE CUT COMPARISON IS NOT A SINGLE EQUALITY ANY MORE. Requiring the live tail to equal
/// `source_cut_chirho` exactly was safe only while an active handoff froze EVERY append. Ruled (a)
/// creates exactly one mutation that can move that tail — the winner-side compensation append — so
/// the first committed compensation would otherwise make its own handoff un-restorable and fail
/// actor startup.
///
/// WHAT REPLACED IT, and it is stricter in the dimension that matters rather than looser: the cut's
/// own content-addressed anchor stays EXACT on the fast path (epoch, seq, AND record digest), and
/// any drift past it must be READ and CLASSIFIED — every intervening record must be
/// compensation-CLASS, and the traversal must REACH THE ANCHOR. "Close enough" is never accepted;
/// the comparison became semantic, not lenient.
///
/// CLASS IS NOT LAWFULNESS, and this line used to say it was. Which reconciliation a record belongs
/// to is fork-impossible to establish here; whether its key is a genuinely derived coordinate is
/// privacy-gated and unbuilt, so a fabricated compensation-lineage key still passes. Both residuals,
/// with their named cures, are at `verify_post_cut_extension_class_and_anchor_chirho`.
///
/// PRECISE SCOPE, unchanged from when this consequence was first recorded: the transferred evidence
/// OBJECTS are untouched. They are content-addressed and immutable, and an append extends the
/// journal without rewriting anything a digest names. What a post-cut append invalidated was this
/// LIVENESS comparison, never the evidence.
fn verify_historical_cut_chirho(
    resident_chirho: &ResidentLedgerAuthorityChirho<'_>,
    guard_chirho: &LocalAppendHandoffGenerationGuardChirho<'_>,
    current_chirho: &ActiveGd7WinnerHandoffChirho,
) -> Result<ResidentLedgerAuthorityReadinessChirho, ResidentGd7WinnerHandoffRefusalChirho> {
    // FOUR DISTINCT CAUSES, FOUR DISTINCT REASONS. Every refusal below used to collapse into
    // `WinnerStateChangedChirho`, which made both pre-registered review arms unassertable: an arm
    // asserting that variant cannot tell whether the digest check, the snapshot floors, the guard,
    // or the probe refused, so a regression in one while another happens to fire reads as green.
    if guard_chirho.handoff_digest_chirho() != current_chirho.attempt_digest_chirho {
        return Err(ResidentGd7WinnerHandoffRefusalChirho::HistoricalCutAttemptMismatchChirho);
    }
    let readiness_chirho = resident_chirho
        .probe_during_handoff_chirho(guard_chirho)
        .map_err(|_error_chirho| {
            ResidentGd7WinnerHandoffRefusalChirho::HistoricalCutProbeFailedChirho
        })?;
    verify_historical_readiness_chirho(&readiness_chirho, current_chirho)?;

    // HALF (b): the cut is pinned by identity above; anything appended PAST it must be read and
    // classified. Exact tail equality is the fast path — no extension, nothing to walk. Otherwise
    // every intervening record must be compensation-CLASS and the walk must REACH THE ANCHOR; a
    // prefix that classifies clean is not evidence about records nobody read. NOT "this
    // reconciliation's" — that scoping is fork-impossible here, measured, not merely unbuilt.
    let source_cut_chirho = &current_chirho
        .checkpoint_chirho
        .inspection_chirho
        .bundle_root_chirho
        .source_cut_chirho;
    let tail_is_exactly_the_cut_chirho = readiness_chirho.journal_epoch_chirho
        == source_cut_chirho.epoch_chirho
        && readiness_chirho.journal_tail_seq_chirho == source_cut_chirho.seq_chirho
        && readiness_chirho.journal_tail_digest_chirho.0 == source_cut_chirho.record_digest_chirho;
    if !tail_is_exactly_the_cut_chirho {
        resident_chirho
            .verify_post_cut_extension_class_and_anchor_chirho(
                source_cut_chirho.seq_chirho,
                &source_cut_chirho.record_digest_chirho,
            )
            // The traversal's typed reason is PRESERVED, not discarded. This `map_err` used to be
            // `|_error_chirho|`, which threw away the one thing an arm needs to assert.
            .map_err(|error_chirho| {
                ResidentGd7WinnerHandoffRefusalChirho::HistoricalCutExtensionRefusedChirho {
                    detail_chirho: error_chirho.to_string(),
                }
            })?;
    }
    Ok(readiness_chirho)
}

/// SNAPSHOT FLOORS ONLY — **THIS IS NOT A TAIL VALIDATION.** Do not call it alone.
///
/// It checks identity, node, term floor, genesis, and that the evidence cut equals the bundle root's
/// source cut. Its epoch and seq comparisons are FLOORS, not equalities, and it does not look at the
/// tail digest at all. On its own it therefore ADMITS a tail that has drifted past the cut.
///
/// The strictness that used to live here moved UP to its single caller,
/// [`verify_historical_cut_chirho`], which is the only production caller and which follows this with
/// an exact epoch+seq+digest fast path or a full classified traversal of the extension. Safety is a
/// property of that pair, never of this function.
///
/// Kept separate rather than folded in only because the caller reads better in two steps. If a
/// SECOND caller ever appears, that is a defect: either it must perform the same
/// exact-or-traverse discipline, or this must be folded into its owner. A previous version of this
/// comment described strict behaviour and argued against ever loosening the comparison — it survived
/// the loosening and sat here asserting the opposite of what the code did, which is precisely the
/// trap the house name-hazard rule exists for.
fn verify_historical_readiness_chirho(
    readiness_chirho: &ResidentLedgerAuthorityReadinessChirho,
    current_chirho: &ActiveGd7WinnerHandoffChirho,
) -> Result<(), ResidentGd7WinnerHandoffRefusalChirho> {
    let checkpoint_chirho = &current_chirho.checkpoint_chirho;
    let held_transfer_identity_chirho = &checkpoint_chirho
        .attempt_identity_chirho
        .held_transfer_identity_chirho;
    let evidence_chirho = &checkpoint_chirho.inspection_chirho.evidence_chirho;
    let root_chirho = &checkpoint_chirho.inspection_chirho.bundle_root_chirho;
    let actual_group_digest_chirho =
        consistency_group_digest_chirho(&readiness_chirho.consistency_group_chirho)
            .map_err(|_| ResidentGd7WinnerHandoffRefusalChirho::WinnerStateChangedChirho)?;
    if actual_group_digest_chirho != held_transfer_identity_chirho.consistency_group_digest_chirho
        || readiness_chirho.local_node_chirho.0 != held_transfer_identity_chirho.winner_node_chirho
        || readiness_chirho.published_raft_term_chirho
            < held_transfer_identity_chirho.winner_term_chirho
        || readiness_chirho.genesis_digest_chirho.0
            != root_chirho.winner_journal_genesis_digest_chirho
        || readiness_chirho.journal_epoch_chirho < root_chirho.source_cut_chirho.epoch_chirho
        || readiness_chirho.journal_tail_seq_chirho < root_chirho.source_cut_chirho.seq_chirho
        || evidence_chirho.latest_verified_journal_cut_chirho != root_chirho.source_cut_chirho
    {
        return Err(ResidentGd7WinnerHandoffRefusalChirho::HistoricalCutSnapshotRefusedChirho);
    }
    Ok(())
}

fn active_from_committed_chirho(
    committed_chirho: crate::reconciliation_chirho::CommittedGd7WinnerHandoffChirho,
) -> ActiveGd7WinnerHandoffChirho {
    ActiveGd7WinnerHandoffChirho {
        attempt_digest_chirho: committed_chirho.attempt_digest_chirho,
        checkpoint_ref_chirho: committed_chirho.checkpoint_ref_chirho,
        checkpoint_chirho: committed_chirho.checkpoint_chirho,
    }
}

fn status_from_active_chirho(
    active_chirho: &ActiveGd7WinnerHandoffChirho,
) -> ResidentGd7WinnerHandoffStatusChirho {
    ResidentGd7WinnerHandoffStatusChirho {
        attempt_digest_chirho: active_chirho.attempt_digest_chirho.clone(),
        checkpoint_ref_chirho: active_chirho.checkpoint_ref_chirho.clone(),
        attempt_identity_chirho: active_chirho
            .checkpoint_chirho
            .attempt_identity_chirho
            .clone(),
        phase_chirho: active_chirho.checkpoint_chirho.phase_chirho,
        inspection_chirho: active_chirho.checkpoint_chirho.inspection_chirho.clone(),
        preparing_process_generation_chirho: active_chirho
            .checkpoint_chirho
            .preparing_process_generation_chirho,
        accepting_process_generation_chirho: active_chirho
            .checkpoint_chirho
            .accepting_process_generation_chirho,
    }
}

#[cfg(test)]
#[path = "winner_handoff_tests_chirho.rs"]
mod tests_chirho;
