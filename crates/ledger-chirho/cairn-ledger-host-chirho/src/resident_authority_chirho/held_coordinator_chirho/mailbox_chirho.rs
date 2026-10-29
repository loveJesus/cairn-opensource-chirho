// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Fixed-capacity command mailbox and client lifecycle for the held GD7 coordinator.
//!
//! The actor-owned command execution remains in the parent module. This module owns only bounded
//! request admission, request/reply waiting, fail-stop inspection, and thread-handle cleanup.

use super::{
    ResidentGd7HeldAdoptionCommitOutcomeChirho,
    ResidentGd7HeldAdoptionMaterializationRequestChirho, ResidentGd7HeldBootstrapSnapshotChirho,
    ResidentGd7HeldCoordinatorRefusalChirho, ResidentGd7HeldCoordinatorSnapshotChirho,
    ResidentGd7HeldObservationImportChirho, ResidentGd7HeldPreparedAdoptionChirho,
    ResidentGd7HeldSealedPlanSnapshotChirho,
};
use crate::reconciliation_chirho::{
    Gd7LosingEffectObligationSelectorChirho, MintedGd7LosingEffectObligationChirho,
    MAX_GD7_WINNER_FIRST_RECORD_INDEX_BYTES_CHIRHO, MAX_GD7_WINNER_FORK_WITNESS_BYTES_CHIRHO,
};
use anyhow::{anyhow, bail, Context, Result};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

const RESIDENT_GD7_HELD_COORDINATOR_MAILBOX_CAPACITY_CHIRHO: usize = 8;
const RESIDENT_GD7_HELD_INSPECTION_TIMEOUT_CHIRHO: Duration = Duration::from_secs(2);

#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants must carry the Chirho suffix"
)]
pub(super) enum ResidentGd7HeldCoordinatorCommandChirho {
    BootstrapChirho {
        reply_chirho: SyncSender<
            std::result::Result<
                ResidentGd7HeldBootstrapSnapshotChirho,
                ResidentGd7HeldCoordinatorRefusalChirho,
            >,
        >,
    },
    InspectChirho {
        reply_chirho: SyncSender<
            std::result::Result<
                ResidentGd7HeldCoordinatorSnapshotChirho,
                ResidentGd7HeldCoordinatorRefusalChirho,
            >,
        >,
    },
    InstallObservationChirho {
        import_chirho: Box<ResidentGd7HeldObservationImportChirho>,
        reply_chirho: SyncSender<
            std::result::Result<
                ResidentGd7HeldCoordinatorSnapshotChirho,
                ResidentGd7HeldCoordinatorRefusalChirho,
            >,
        >,
    },
    AdvanceOnePageChirho {
        expected_checkpoint_ref_chirho: String,
        reply_chirho: SyncSender<
            std::result::Result<
                ResidentGd7HeldCoordinatorSnapshotChirho,
                ResidentGd7HeldCoordinatorRefusalChirho,
            >,
        >,
    },
    VerifySealedPlanChirho {
        expected_checkpoint_ref_chirho: String,
        reply_chirho: SyncSender<
            std::result::Result<
                ResidentGd7HeldSealedPlanSnapshotChirho,
                ResidentGd7HeldCoordinatorRefusalChirho,
            >,
        >,
    },
    PrepareAdoptionMaterializationChirho {
        request_chirho: Box<ResidentGd7HeldAdoptionMaterializationRequestChirho>,
        reply_chirho: SyncSender<
            std::result::Result<
                ResidentGd7HeldPreparedAdoptionChirho,
                ResidentGd7HeldCoordinatorRefusalChirho,
            >,
        >,
    },
    CommitAdoptionChirho {
        prepared_chirho: Box<ResidentGd7HeldPreparedAdoptionChirho>,
        reply_chirho: SyncSender<
            std::result::Result<
                ResidentGd7HeldAdoptionCommitOutcomeChirho,
                ResidentGd7HeldCoordinatorRefusalChirho,
            >,
        >,
    },
    /// The request carries a SELECTOR and nothing else — no digest, no subject, no authority.
    ///
    /// The minted value travels back by MOVE, which is the affine discipline surviving the mailbox
    /// boundary rather than being suspended at it: `MintedGd7LosingEffectObligationChirho` is
    /// deliberately not `Clone`, and a channel send transfers it, so exactly one receiver ever
    /// holds the receipt.
    MintLosingEffectObligationChirho {
        selector_chirho: Box<Gd7LosingEffectObligationSelectorChirho>,
        reply_chirho: SyncSender<
            std::result::Result<
                MintedGd7LosingEffectObligationChirho,
                ResidentGd7HeldCoordinatorRefusalChirho,
            >,
        >,
    },
}

pub(super) type ResidentGd7HeldCoordinatorCommandReceiverChirho =
    Receiver<ResidentGd7HeldCoordinatorCommandChirho>;

/// Fixed-mailbox process handle for held-only GD7 inspection.
pub struct ResidentGd7HeldCoordinatorHandleChirho {
    command_sender_chirho: Option<SyncSender<ResidentGd7HeldCoordinatorCommandChirho>>,
    actor_thread_chirho: Option<JoinHandle<()>>,
}

#[derive(Clone)]
struct ResidentGd7HeldCoordinatorInspectorChirho {
    command_sender_chirho: SyncSender<ResidentGd7HeldCoordinatorCommandChirho>,
}

/// Fail-stop monitor for one held coordinator and its shared process stop flag.
pub struct ResidentGd7HeldCoordinatorMonitorChirho {
    stop_chirho: Arc<AtomicBool>,
    monitor_thread_chirho:
        Option<JoinHandle<std::result::Result<(), ResidentGd7HeldCoordinatorRefusalChirho>>>,
}

pub(super) fn open_resident_gd7_held_coordinator_mailbox_chirho() -> (
    SyncSender<ResidentGd7HeldCoordinatorCommandChirho>,
    ResidentGd7HeldCoordinatorCommandReceiverChirho,
) {
    sync_channel(RESIDENT_GD7_HELD_COORDINATOR_MAILBOX_CAPACITY_CHIRHO)
}

impl ResidentGd7HeldCoordinatorHandleChirho {
    pub(super) fn new_chirho(
        command_sender_chirho: SyncSender<ResidentGd7HeldCoordinatorCommandChirho>,
        actor_thread_chirho: JoinHandle<()>,
    ) -> Self {
        Self {
            command_sender_chirho: Some(command_sender_chirho),
            actor_thread_chirho: Some(actor_thread_chirho),
        }
    }

    pub fn bootstrap_chirho(
        &self,
    ) -> std::result::Result<
        ResidentGd7HeldBootstrapSnapshotChirho,
        ResidentGd7HeldCoordinatorRefusalChirho,
    > {
        let inspector_chirho = ResidentGd7HeldCoordinatorInspectorChirho {
            command_sender_chirho: self
                .command_sender_chirho
                .as_ref()
                .ok_or(ResidentGd7HeldCoordinatorRefusalChirho::UnavailableChirho)?
                .clone(),
        };
        inspector_chirho.bootstrap_chirho()
    }

    pub fn inspect_chirho(
        &self,
    ) -> std::result::Result<
        ResidentGd7HeldCoordinatorSnapshotChirho,
        ResidentGd7HeldCoordinatorRefusalChirho,
    > {
        let inspector_chirho = ResidentGd7HeldCoordinatorInspectorChirho {
            command_sender_chirho: self
                .command_sender_chirho
                .as_ref()
                .ok_or(ResidentGd7HeldCoordinatorRefusalChirho::UnavailableChirho)?
                .clone(),
        };
        inspector_chirho.inspect_chirho()
    }

    /// Verify and install one exact winner observation, then return the durable active checkpoint.
    ///
    /// Once the fixed mailbox accepts this mutation, the caller waits for its exact result instead
    /// of timing out while the actor could still commit it.
    pub fn install_authenticated_observation_chirho(
        &self,
        import_chirho: ResidentGd7HeldObservationImportChirho,
    ) -> std::result::Result<
        ResidentGd7HeldCoordinatorSnapshotChirho,
        ResidentGd7HeldCoordinatorRefusalChirho,
    > {
        if import_chirho.winner_first_record_index_bytes_chirho.len()
            > MAX_GD7_WINNER_FIRST_RECORD_INDEX_BYTES_CHIRHO
            || import_chirho.winner_fork_witness_bytes_chirho.len()
                > MAX_GD7_WINNER_FORK_WITNESS_BYTES_CHIRHO
        {
            return Err(ResidentGd7HeldCoordinatorRefusalChirho::ObservationOversizedChirho);
        }
        let command_sender_chirho = self
            .command_sender_chirho
            .as_ref()
            .ok_or(ResidentGd7HeldCoordinatorRefusalChirho::UnavailableChirho)?;
        send_held_mutation_chirho(command_sender_chirho, |reply_chirho| {
            ResidentGd7HeldCoordinatorCommandChirho::InstallObservationChirho {
                import_chirho: Box::new(import_chirho),
                reply_chirho,
            }
        })
    }

    /// Advance exactly one manifest or plan page from the caller's exact checkpoint reference.
    pub fn advance_one_page_chirho(
        &self,
        expected_checkpoint_ref_chirho: String,
    ) -> std::result::Result<
        ResidentGd7HeldCoordinatorSnapshotChirho,
        ResidentGd7HeldCoordinatorRefusalChirho,
    > {
        let command_sender_chirho = self
            .command_sender_chirho
            .as_ref()
            .ok_or(ResidentGd7HeldCoordinatorRefusalChirho::UnavailableChirho)?;
        send_held_mutation_chirho(command_sender_chirho, |reply_chirho| {
            ResidentGd7HeldCoordinatorCommandChirho::AdvanceOnePageChirho {
                expected_checkpoint_ref_chirho,
                reply_chirho,
            }
        })
    }

    /// Reverify the complete immutable plan chain named by one exact sealed checkpoint.
    pub fn verify_sealed_plan_chirho(
        &self,
        expected_checkpoint_ref_chirho: String,
    ) -> std::result::Result<
        ResidentGd7HeldSealedPlanSnapshotChirho,
        ResidentGd7HeldCoordinatorRefusalChirho,
    > {
        let command_sender_chirho = self
            .command_sender_chirho
            .as_ref()
            .ok_or(ResidentGd7HeldCoordinatorRefusalChirho::UnavailableChirho)?;
        send_held_mutation_chirho(command_sender_chirho, |reply_chirho| {
            ResidentGd7HeldCoordinatorCommandChirho::VerifySealedPlanChirho {
                expected_checkpoint_ref_chirho,
                reply_chirho,
            }
        })
    }

    /// Ensure the exact read-only branch and materialize immutable adoption candidates.
    ///
    /// This Cut A command does not change phase or grant authority. Once the bounded mailbox
    /// accepts it, the caller waits for the actor's exact result rather than timing out while a
    /// durable candidate may still be materializing.
    pub fn prepare_adoption_materialization_chirho(
        &self,
        request_chirho: ResidentGd7HeldAdoptionMaterializationRequestChirho,
    ) -> std::result::Result<
        ResidentGd7HeldPreparedAdoptionChirho,
        ResidentGd7HeldCoordinatorRefusalChirho,
    > {
        let command_sender_chirho = self
            .command_sender_chirho
            .as_ref()
            .ok_or(ResidentGd7HeldCoordinatorRefusalChirho::UnavailableChirho)?;
        send_held_mutation_chirho(command_sender_chirho, |reply_chirho| {
            ResidentGd7HeldCoordinatorCommandChirho::PrepareAdoptionMaterializationChirho {
                request_chirho: Box::new(request_chirho),
                reply_chirho,
            }
        })
    }

    /// Commit or fully reverify one exact prepared adoption selector.
    ///
    /// The fixed reconciliation head remains present after this command, so adoption grants no
    /// write authority. A retry reports `AlreadyAdoptedExactChirho` only after restart-equivalent
    /// verification of the immutable candidate pair. That read-only exact retry may survive a
    /// same-winner term rollover; the initial head mutation remains historical-term exact.
    pub fn commit_adoption_chirho(
        &self,
        prepared_chirho: ResidentGd7HeldPreparedAdoptionChirho,
    ) -> std::result::Result<
        ResidentGd7HeldAdoptionCommitOutcomeChirho,
        ResidentGd7HeldCoordinatorRefusalChirho,
    > {
        let command_sender_chirho = self
            .command_sender_chirho
            .as_ref()
            .ok_or(ResidentGd7HeldCoordinatorRefusalChirho::UnavailableChirho)?;
        send_held_mutation_chirho(command_sender_chirho, |reply_chirho| {
            ResidentGd7HeldCoordinatorCommandChirho::CommitAdoptionChirho {
                prepared_chirho: Box::new(prepared_chirho),
                reply_chirho,
            }
        })
    }

    /// Mint one exact actor-owned GD7 losing-effect obligation from the adopted sealed plan.
    ///
    /// THE SIXTH held-coordinator command, and the only producer of the three coordinates a GD7
    /// compensation composition needs. `selector_chirho` names WHICH obligation — a content-addressed
    /// plan page ref and an index within it. It cannot name WHOSE: the actor supplies the expected
    /// reconciliation identity from its own loaded checkpoint, so a caller cannot mint against a
    /// subject it chose. Filing a row for an obligation nobody minted is forging the subject, and
    /// this signature is why that is unrepresentable here rather than merely refused.
    ///
    /// The mint is durable and idempotent on its selector: an exact replay reports the same receipt
    /// rather than claiming a second obligation. A refusal carrying `receipt_ref_chirho` means the
    /// receipt EXISTS and is awaiting a verified item-5b resume — that case must not be retried as
    /// though nothing happened.
    pub fn mint_losing_effect_obligation_chirho(
        &self,
        selector_chirho: Gd7LosingEffectObligationSelectorChirho,
    ) -> std::result::Result<
        MintedGd7LosingEffectObligationChirho,
        ResidentGd7HeldCoordinatorRefusalChirho,
    > {
        let command_sender_chirho = self
            .command_sender_chirho
            .as_ref()
            .ok_or(ResidentGd7HeldCoordinatorRefusalChirho::UnavailableChirho)?;
        send_held_mutation_chirho(command_sender_chirho, |reply_chirho| {
            ResidentGd7HeldCoordinatorCommandChirho::MintLosingEffectObligationChirho {
                selector_chirho: Box::new(selector_chirho),
                reply_chirho,
            }
        })
    }

    /// Continuously revalidate the held election/checkpoint/journal tuple. Any refusal sets the same
    /// stop flag used by the transport, so the network process exits instead of serving after drift.
    pub fn start_fail_stop_monitor_chirho(
        &self,
        stop_chirho: Arc<AtomicBool>,
        interval_chirho: Duration,
    ) -> Result<ResidentGd7HeldCoordinatorMonitorChirho> {
        if interval_chirho.is_zero() {
            bail!("held GD7 monitor interval must be positive");
        }
        let inspector_chirho = ResidentGd7HeldCoordinatorInspectorChirho {
            command_sender_chirho: self
                .command_sender_chirho
                .as_ref()
                .ok_or_else(|| anyhow!("held GD7 coordinator is unavailable"))?
                .clone(),
        };
        let monitor_stop_chirho = Arc::clone(&stop_chirho);
        let monitor_thread_chirho = std::thread::Builder::new()
            .name("resident-gd7-held-monitor-chirho".to_owned())
            .spawn(move || {
                while !monitor_stop_chirho.load(Ordering::Acquire) {
                    if let Err(error_chirho) = inspector_chirho.bootstrap_chirho() {
                        monitor_stop_chirho.store(true, Ordering::Release);
                        return Err(error_chirho);
                    }
                    std::thread::park_timeout(interval_chirho);
                }
                Ok(())
            })
            .context("spawn held GD7 fail-stop monitor")?;
        Ok(ResidentGd7HeldCoordinatorMonitorChirho {
            stop_chirho,
            monitor_thread_chirho: Some(monitor_thread_chirho),
        })
    }

    pub fn close_chirho(&mut self) -> Result<()> {
        self.command_sender_chirho.take();
        let actor_thread_chirho = self
            .actor_thread_chirho
            .take()
            .ok_or_else(|| anyhow!("held GD7 coordinator is already closed"))?;
        actor_thread_chirho
            .join()
            .map_err(|_panic_chirho| anyhow!("held GD7 coordinator actor panicked"))
    }
}

impl ResidentGd7HeldCoordinatorInspectorChirho {
    fn bootstrap_chirho(
        &self,
    ) -> std::result::Result<
        ResidentGd7HeldBootstrapSnapshotChirho,
        ResidentGd7HeldCoordinatorRefusalChirho,
    > {
        send_held_inspection_chirho(&self.command_sender_chirho, |reply_chirho| {
            ResidentGd7HeldCoordinatorCommandChirho::BootstrapChirho { reply_chirho }
        })
    }

    fn inspect_chirho(
        &self,
    ) -> std::result::Result<
        ResidentGd7HeldCoordinatorSnapshotChirho,
        ResidentGd7HeldCoordinatorRefusalChirho,
    > {
        send_held_inspection_chirho(&self.command_sender_chirho, |reply_chirho| {
            ResidentGd7HeldCoordinatorCommandChirho::InspectChirho { reply_chirho }
        })
    }
}

fn send_held_inspection_chirho<ReplyChirho>(
    command_sender_chirho: &SyncSender<ResidentGd7HeldCoordinatorCommandChirho>,
    command_chirho: impl FnOnce(
        SyncSender<std::result::Result<ReplyChirho, ResidentGd7HeldCoordinatorRefusalChirho>>,
    ) -> ResidentGd7HeldCoordinatorCommandChirho,
) -> std::result::Result<ReplyChirho, ResidentGd7HeldCoordinatorRefusalChirho> {
    let (reply_sender_chirho, reply_receiver_chirho) = sync_channel(1);
    match command_sender_chirho.try_send(command_chirho(reply_sender_chirho)) {
        Ok(()) => {}
        Err(TrySendError::Full(_command_chirho)) => {
            return Err(ResidentGd7HeldCoordinatorRefusalChirho::MailboxFullChirho);
        }
        Err(TrySendError::Disconnected(_command_chirho)) => {
            return Err(ResidentGd7HeldCoordinatorRefusalChirho::UnavailableChirho);
        }
    }
    reply_receiver_chirho
        .recv_timeout(RESIDENT_GD7_HELD_INSPECTION_TIMEOUT_CHIRHO)
        .map_err(|error_chirho| match error_chirho {
            RecvTimeoutError::Timeout => {
                ResidentGd7HeldCoordinatorRefusalChirho::InspectionTimedOutChirho
            }
            RecvTimeoutError::Disconnected => {
                ResidentGd7HeldCoordinatorRefusalChirho::UnavailableChirho
            }
        })?
}

fn send_held_mutation_chirho<ReplyChirho>(
    command_sender_chirho: &SyncSender<ResidentGd7HeldCoordinatorCommandChirho>,
    command_chirho: impl FnOnce(
        SyncSender<std::result::Result<ReplyChirho, ResidentGd7HeldCoordinatorRefusalChirho>>,
    ) -> ResidentGd7HeldCoordinatorCommandChirho,
) -> std::result::Result<ReplyChirho, ResidentGd7HeldCoordinatorRefusalChirho> {
    let (reply_sender_chirho, reply_receiver_chirho) = sync_channel(1);
    match command_sender_chirho.try_send(command_chirho(reply_sender_chirho)) {
        Ok(()) => {}
        Err(TrySendError::Full(_command_chirho)) => {
            return Err(ResidentGd7HeldCoordinatorRefusalChirho::MailboxFullChirho);
        }
        Err(TrySendError::Disconnected(_command_chirho)) => {
            return Err(ResidentGd7HeldCoordinatorRefusalChirho::UnavailableChirho);
        }
    }
    reply_receiver_chirho
        .recv()
        .map_err(|_error_chirho| ResidentGd7HeldCoordinatorRefusalChirho::UnavailableChirho)?
}

impl ResidentGd7HeldCoordinatorMonitorChirho {
    pub fn close_chirho(&mut self) -> Result<()> {
        self.stop_chirho.store(true, Ordering::Release);
        let monitor_thread_chirho = self
            .monitor_thread_chirho
            .take()
            .ok_or_else(|| anyhow!("held GD7 fail-stop monitor is already closed"))?;
        monitor_thread_chirho.thread().unpark();
        monitor_thread_chirho
            .join()
            .map_err(|_panic_chirho| anyhow!("held GD7 fail-stop monitor panicked"))?
            .map_err(|error_chirho| anyhow!(error_chirho))
    }
}

impl Drop for ResidentGd7HeldCoordinatorMonitorChirho {
    fn drop(&mut self) {
        self.stop_chirho.store(true, Ordering::Release);
        if let Some(monitor_thread_chirho) = self.monitor_thread_chirho.take() {
            monitor_thread_chirho.thread().unpark();
            let _join_result_chirho = monitor_thread_chirho.join();
        }
    }
}

impl Drop for ResidentGd7HeldCoordinatorHandleChirho {
    fn drop(&mut self) {
        self.command_sender_chirho.take();
        if let Some(actor_thread_chirho) = self.actor_thread_chirho.take() {
            let _join_result_chirho = actor_thread_chirho.join();
        }
    }
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    #[test]
    fn held_coordinator_mailbox_refuses_before_unbounded_acceptance_chirho() {
        let (sender_chirho, receiver_chirho) =
            sync_channel(RESIDENT_GD7_HELD_COORDINATOR_MAILBOX_CAPACITY_CHIRHO);
        let mut retained_replies_chirho = Vec::new();
        for _slot_chirho in 0..RESIDENT_GD7_HELD_COORDINATOR_MAILBOX_CAPACITY_CHIRHO {
            let (reply_sender_chirho, reply_receiver_chirho) = sync_channel(1);
            sender_chirho
                .try_send(ResidentGd7HeldCoordinatorCommandChirho::InspectChirho {
                    reply_chirho: reply_sender_chirho,
                })
                .expect("each fixed mailbox slot accepts exactly one command");
            retained_replies_chirho.push(reply_receiver_chirho);
        }
        let handle_chirho = ResidentGd7HeldCoordinatorHandleChirho {
            command_sender_chirho: Some(sender_chirho),
            actor_thread_chirho: None,
        };
        assert_eq!(
            handle_chirho.inspect_chirho().unwrap_err(),
            ResidentGd7HeldCoordinatorRefusalChirho::MailboxFullChirho
        );
        drop(receiver_chirho);
        drop(retained_replies_chirho);
    }
}
