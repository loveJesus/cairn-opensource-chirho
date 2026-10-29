// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Bounded GD7 reconciliation coordination on a held multi-node follower.
//!
//! The caller supplies the exact `Arc<RaftWriterElectorChirho>` already driven by the cluster
//! transport. Schema v3 remains inspection-only. Schema v4 can verify and persist immutable winner
//! evidence, install `ObservedHeld`, alternate one bounded manifest/plan page, reverify a sealed
//! plan, materialize the exact Cut A journal/projection pair, and atomically select that pair as
//! `AdoptedHeld` using the existing node key plus public ledger verifier pins. This actor never
//! campaigns, ticks, appends a ledger record, compensates, moves a served or application ref,
//! releases the winner barrier, or enables writes.
//! The immutable reconciliation identity keeps its historical winner term. Only read-only startup,
//! bootstrap/monitor, inspection, and a fully restart-verified exact-adoption retry may observe the
//! same winner at a later term. Every state-producing command, including the `PlanSealed` to
//! `AdoptedHeld` head mutation, remains historical-term exact; no actor-owned retained-barrier proof
//! is threaded into those mutations yet.
//! Workflow:
//! `spec-chirho/workflows-chirho/distributed-ha-chirho/cf8-gd7-deposed-fork-reconciliation-design-chirho.md`.

#[path = "held_coordinator_chirho/adoption_chirho.rs"]
mod adoption_chirho;
#[path = "held_coordinator_chirho/adoption_commit_actor_chirho.rs"]
mod adoption_commit_actor_chirho;
#[path = "held_coordinator_chirho/adoption_commit_chirho.rs"]
mod adoption_commit_chirho;
#[path = "held_coordinator_chirho/election_chirho.rs"]
mod election_chirho;
#[path = "held_coordinator_chirho/losing_journal_chirho.rs"]
mod losing_journal_chirho;
#[path = "held_coordinator_chirho/mailbox_chirho.rs"]
mod mailbox_chirho;

use crate::reconciliation_chirho::Gd7PlanRefusalChirho;

pub use adoption_chirho::{
    ResidentGd7HeldAdoptionMaterializationRefusalChirho, ResidentGd7HeldPreparedAdoptionChirho,
};
pub use adoption_commit_chirho::{
    ResidentGd7HeldAdoptedSnapshotChirho, ResidentGd7HeldAdoptionCommitOutcomeChirho,
    ResidentGd7HeldAdoptionCommitRefusalChirho,
};
pub use mailbox_chirho::{
    ResidentGd7HeldCoordinatorHandleChirho, ResidentGd7HeldCoordinatorMonitorChirho,
};

use crate::custody_chirho::verify_host_ledger_config_custody_chirho;
use crate::reconciliation_chirho::{
    drive_authenticated_losing_manifest_page_chirho,
    ensure_authenticated_deposed_fork_observed_held_chirho,
    load_authenticated_active_gd7_reconciliation_for_group_chirho, ActiveGd7ReconciliationChirho,
    AuthenticatedGd7DeposedForkObservationChirho, ExistingNodeGd7SignerChirho,
    Gd7EffectProofPortsChirho, Gd7HeldEvidenceTransferIdentityChirho,
    Gd7HeldEvidenceTransferPhaseChirho, Gd7HeldEvidenceTransferStoreChirho,
    Gd7ManifestPageBudgetChirho, Gd7ReconciliationIdentityChirho, Gd7ReconciliationPhaseChirho,
    Gd7ReconciliationSignerPortChirho, Gd7WinnerWitnessReaderChirho, PinnedNodeGd7VerifierChirho,
    RootGd7EffectEvidenceReaderChirho, VerifiedGd7SealedPlanProofChirho,
};
use crate::resident_authority_chirho::runtime_actor_chirho::{
    ResidentGd7PlanPortsChirho, RESIDENT_EFFECT_JOURNAL_CANARY_DIR_CHIRHO,
};
use crate::signer_chirho::HostLedgerHeldVerifiersChirho;
use crate::storage_chirho::{FsLedgerStorageChirho, StableLedgerExclusiveLockGuardChirho};
use crate::ResidentLedgerClockChirho;
#[cfg(test)]
pub(crate) use adoption_chirho::{
    gd7_adoption_staging_journal_path_for_test_chirho,
    materialize_gd7_held_adoption_candidate_with_projection_for_test_chirho,
};
pub(crate) use adoption_chirho::{
    materialize_gd7_held_adoption_candidate_chirho, Gd7HeldAdoptionMaterializationPortsChirho,
};
pub(crate) use adoption_commit_actor_chirho::ResidentGd7HeldObligationMintActorPortsChirho;
use adoption_commit_actor_chirho::{
    commit_or_reload_actor_owned_gd7_held_adoption_chirho,
    mint_actor_owned_gd7_losing_effect_obligation_chirho,
    verify_actor_owned_gd7_held_adoption_startup_chirho, ResidentGd7HeldAdoptionActorPortsChirho,
};
// THE `ForTest` ALIASES ARE GONE FROM THE TWO TYPES, and that is a correctness change rather than
// tidying. Both were imported as `...ForTestChirho` while the mint had no production caller. It has
// one now — the sixth held-coordinator command below — so a reader meeting `...ForTestChirho` in the
// crate's own tests would be told by the name that the ports and refusal are test-only, which is the
// documented failure mode of a name asserting the opposite of what it holds. The HOOK entry keeps
// its suffix because it really is test-only.
#[cfg(test)]
pub(crate) use adoption_commit_actor_chirho::mint_actor_owned_gd7_losing_effect_obligation_with_hooks_for_test_chirho;
pub use adoption_commit_actor_chirho::ResidentGd7HeldObligationMintRefusalChirho;
#[cfg(test)]
pub(crate) use adoption_commit_chirho::{
    commit_or_reload_gd7_held_adoption_chirho as commit_or_reload_gd7_held_adoption_for_test_chirho,
    verify_active_gd7_held_adoption_chirho as verify_active_gd7_held_adoption_for_test_chirho,
    Gd7HeldAdoptionCommitPortsChirho as Gd7HeldAdoptionCommitPortsForTestChirho,
};
use anyhow::{anyhow, bail, Context, Result};
use cairn_config_chirho::config_chirho::{
    LedgerHostConfigChirho, LEDGER_HOST_CONFIG_SCHEMA_V4_CHIRHO,
};
use cairn_ledger_log_chirho::admission_chirho::{
    AuthorityVerdictChirho, AuthorityVerifierViewChirho, KindRegistryViewChirho,
    KindResolutionChirho, MembershipStatusChirho, MembershipViewChirho,
};
use cairn_ledger_log_chirho::journal_chirho::JournalPortsChirho;
use cairn_ledger_log_chirho::losing_suffix_chirho::{
    LosingSuffixReaderChirho, VerifiedLosingJournalTailChirho, MAX_LOSING_SUFFIX_PAGE_BYTES_CHIRHO,
    MAX_LOSING_SUFFIX_PAGE_RECORDS_CHIRHO,
};
use cairn_ledger_log_chirho::ports_chirho::StoragePathChirho;
use cairn_ledger_model_chirho::ids_chirho::{
    AccountIdChirho, AssetKindIdChirho, AssetKindRefChirho, ClusterIdChirho, DigestChirho,
};
use cairn_ledger_model_chirho::ShardEpochChirho;
use cairn_seqlog_chirho::seqlog_chirho::named_lock_storage_key_chirho;
use cairn_writer_elector_chirho::elector_port_chirho::{NodeIdChirho, WriterElectorChirho};
use cairn_writer_elector_chirho::raft_elector_chirho::RaftWriterElectorChirho;
use cairn_writer_head_chirho::writer_head_chirho::{
    consistency_group_digest_chirho, consistency_group_for_root_chirho, ConsistencyGroupIdChirho,
    WRITER_FENCE_LOCK_CHIRHO,
};
use election_chirho::{
    require_stable_election_observation_chirho, verify_held_bootstrap_election_chirho,
    verify_held_historical_mutation_election_chirho,
    verify_held_read_only_election_observation_chirho, HeldIdentityElectionVerifierChirho,
};
use losing_journal_chirho::{HeldLosingJournalCustodyChirho, HeldLosingJournalIdentityChirho};
use mailbox_chirho::{
    open_resident_gd7_held_coordinator_mailbox_chirho, ResidentGd7HeldCoordinatorCommandChirho,
    ResidentGd7HeldCoordinatorCommandReceiverChirho,
};
use std::error::Error;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{sync_channel, SyncSender};
use std::sync::Arc;

struct HeldReadOnlyKindRegistryChirho;

impl KindRegistryViewChirho for HeldReadOnlyKindRegistryChirho {
    fn resolve_chirho(&self, _policy_ref_chirho: &AssetKindRefChirho) -> KindResolutionChirho {
        KindResolutionChirho::UnknownChirho
    }
}

struct HeldReadOnlyMembershipChirho;

impl MembershipViewChirho for HeldReadOnlyMembershipChirho {
    fn status_chirho(
        &self,
        _account_chirho: &AccountIdChirho,
        _epoch_chirho: ShardEpochChirho,
    ) -> MembershipStatusChirho {
        MembershipStatusChirho::NonMemberChirho
    }
}

struct HeldReadOnlyAuthorityVerifierChirho;

impl AuthorityVerifierViewChirho for HeldReadOnlyAuthorityVerifierChirho {
    fn verify_mint_chirho(
        &self,
        _evidence_chirho: &DigestChirho,
        _kind_id_chirho: &AssetKindIdChirho,
    ) -> AuthorityVerdictChirho {
        AuthorityVerdictChirho::UnverifiedChirho
    }

    fn verify_burn_chirho(
        &self,
        _evidence_chirho: &DigestChirho,
        _kind_id_chirho: &AssetKindIdChirho,
    ) -> AuthorityVerdictChirho {
        AuthorityVerdictChirho::UnverifiedChirho
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResidentGd7HeldCoordinatorSnapshotChirho {
    pub checkpoint_ref_chirho: String,
    pub phase_chirho: Gd7ReconciliationPhaseChirho,
    pub transition_seq_chirho: u64,
    pub consistency_group_digest_chirho: String,
    pub winner_node_chirho: String,
    pub held_node_chirho: String,
    pub winner_term_chirho: u64,
    pub losing_tail_epoch_chirho: u64,
    pub losing_tail_seq_chirho: u64,
    pub losing_tail_digest_chirho: String,
}

/// Exact held/election coordinate used to request or verify an initial winner observation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResidentGd7HeldBootstrapSnapshotChirho {
    pub consistency_group_digest_chirho: String,
    pub winner_node_chirho: String,
    pub held_node_chirho: String,
    pub winner_term_chirho: u64,
    pub losing_journal_genesis_digest_chirho: String,
    pub losing_tail_epoch_chirho: u64,
    pub losing_tail_seq_chirho: u64,
    pub losing_tail_digest_chirho: String,
    pub active_checkpoint_ref_chirho: Option<String>,
}

/// Canonical signed winner evidence admitted to the held coordinator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResidentGd7HeldObservationImportChirho {
    pub identity_chirho: Gd7ReconciliationIdentityChirho,
    pub winner_first_record_index_bytes_chirho: Vec<u8>,
    pub winner_fork_witness_bytes_chirho: Vec<u8>,
}

/// Bounded whole-plan proof returned only after the exact sealed checkpoint re-verifies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResidentGd7HeldSealedPlanSnapshotChirho {
    pub reconciliation_identity_digest_chirho: String,
    pub checkpoint_ref_chirho: String,
    pub sealed_plan_ref_chirho: String,
    pub winner_fork_witness_object_digest_chirho: String,
    pub winner_term_chirho: u64,
    pub plan_page_count_chirho: u64,
    pub manifest_record_count_chirho: u64,
    pub effect_obligation_count_chirho: u64,
}

/// Exact completed transfer coordinate accepted by the actor-owned Cut A materializer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResidentGd7HeldAdoptionMaterializationRequestChirho {
    pub transfer_identity_chirho: Gd7HeldEvidenceTransferIdentityChirho,
    pub expected_evidence_checkpoint_ref_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants must carry the Chirho suffix"
)]
pub enum ResidentGd7HeldCoordinatorRefusalChirho {
    MailboxFullChirho,
    UnavailableChirho,
    InspectionTimedOutChirho,
    ElectorNodeMismatchChirho,
    HeldNodeBecameLeaderChirho,
    NoElectedWinnerObservedChirho,
    WinnerTermRegressedChirho,
    WinnerTermDoesNotDeposeLosingTermChirho,
    WinnerNodeChangedChirho,
    ElectionObservationChangedChirho,
    BootstrapSnapshotChangedChirho,
    NewerWinnerTermWithoutRetainedBarrierChirho,
    CheckpointChangedIdentityChirho,
    CheckpointChirho,
    LosingJournalChangedChirho,
    LiveReconciliationNotConfiguredChirho,
    ObservationOversizedChirho,
    ObservationChirho,
    ManifestChirho,
    /// The plan reducer refused, and its reason survives BY NAME.
    ///
    /// This variant used to be a UNIT that discarded the cause, so a missing warrant, a forged
    /// warrant, a foreign-genesis mismatch, and an immutable collision all presented as the bare
    /// words "held GD7 plan progression failed" — indistinguishable at the mailbox boundary on a
    /// money path. The payload is the reducer's own verdict, not a re-derivation of it.
    PlanChirho(Gd7PlanRefusalChirho),
    /// The coordinator cannot drive a plan page from this phase.
    ///
    /// This is a SEQUENCING refusal, not a plan-reducer verdict — the reducer was never consulted.
    /// It carries the phase rather than a fabricated `Gd7PlanRefusalChirho`, because inventing a
    /// reducer verdict nobody produced is the same defect this split exists to remove.
    UndrivablePhaseChirho(Gd7ReconciliationPhaseChirho),
    SealedPlanChirho,
    AdoptionMaterializationChirho(ResidentGd7HeldAdoptionMaterializationRefusalChirho),
    AdoptionCommitChirho(ResidentGd7HeldAdoptionCommitRefusalChirho),
    /// The actor-owned obligation mint refused, and its reason survives BY NAME.
    ///
    /// The payload matters more here than on its siblings. This mint is the ONLY producer of the
    /// three compose coordinates, so a caller that cannot tell `ActiveAdoptionUnavailable` from
    /// `AdoptionChangedAfterMint { receipt_ref }` cannot tell "nothing was minted, retry is safe"
    /// from "a durable receipt EXISTS and is awaiting resume" — and retrying the second is how one
    /// obligation becomes two.
    ObligationMintChirho(ResidentGd7HeldObligationMintRefusalChirho),
}

impl fmt::Display for ResidentGd7HeldCoordinatorRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message_chirho = match self {
            Self::MailboxFullChirho => "held GD7 coordinator mailbox is full",
            Self::UnavailableChirho => "held GD7 coordinator is unavailable",
            Self::InspectionTimedOutChirho => "held GD7 coordinator inspection timed out",
            Self::ElectorNodeMismatchChirho => {
                "held GD7 coordinator elector belongs to a different local node"
            }
            Self::HeldNodeBecameLeaderChirho => {
                "held GD7 coordinator local node became the elected leader"
            }
            Self::NoElectedWinnerObservedChirho => {
                "held GD7 coordinator observes no elected winner"
            }
            Self::WinnerTermRegressedChirho => {
                "held GD7 coordinator winner term regressed below the historical term"
            }
            Self::WinnerTermDoesNotDeposeLosingTermChirho => {
                "held GD7 coordinator winner term does not depose the losing journal term"
            }
            Self::WinnerNodeChangedChirho => {
                "held GD7 coordinator observes a different elected winner"
            }
            Self::ElectionObservationChangedChirho => {
                "held GD7 coordinator election observation changed during verification"
            }
            Self::BootstrapSnapshotChangedChirho => {
                "held GD7 coordinator bootstrap snapshot changed during observation import"
            }
            Self::NewerWinnerTermWithoutRetainedBarrierChirho => {
                "held GD7 coordinator newer winner term lacks an actor-owned retained barrier"
            }
            Self::CheckpointChangedIdentityChirho => {
                "held GD7 coordinator checkpoint identity changed"
            }
            Self::CheckpointChirho => "held GD7 coordinator checkpoint verification failed",
            Self::LosingJournalChangedChirho => {
                "held GD7 coordinator losing journal differs from its checkpoint"
            }
            Self::LiveReconciliationNotConfiguredChirho => {
                "held GD7 coordinator is not configured for live reconciliation"
            }
            Self::ObservationOversizedChirho => {
                "held GD7 winner observation exceeds its fixed bound"
            }
            Self::ObservationChirho => "held GD7 winner observation verification failed",
            Self::ManifestChirho => "held GD7 manifest progression failed",
            Self::PlanChirho(refusal_chirho) => {
                return write!(
                    formatter_chirho,
                    "held GD7 plan progression refused: {refusal_chirho:?}"
                );
            }
            Self::UndrivablePhaseChirho(phase_chirho) => {
                return write!(
                    formatter_chirho,
                    "held GD7 coordinator cannot drive a plan page from phase {phase_chirho:?}"
                );
            }
            Self::SealedPlanChirho => "held GD7 sealed-plan verification failed",
            Self::AdoptionMaterializationChirho(error_chirho) => {
                return write!(
                    formatter_chirho,
                    "held GD7 adoption materialization refused: {error_chirho}"
                );
            }
            Self::AdoptionCommitChirho(error_chirho) => {
                return write!(
                    formatter_chirho,
                    "held GD7 adoption commit refused: {error_chirho}"
                );
            }
            Self::ObligationMintChirho(error_chirho) => {
                return write!(
                    formatter_chirho,
                    "held GD7 losing-effect obligation mint refused: {error_chirho}"
                );
            }
        };
        formatter_chirho.write_str(message_chirho)
    }
}

impl Error for ResidentGd7HeldCoordinatorRefusalChirho {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::AdoptionMaterializationChirho(error_chirho) => Some(error_chirho),
            Self::AdoptionCommitChirho(error_chirho) => Some(error_chirho),
            Self::ObligationMintChirho(error_chirho) => Some(error_chirho),
            _ => None,
        }
    }
}

impl From<ResidentGd7HeldAdoptionMaterializationRefusalChirho>
    for ResidentGd7HeldCoordinatorRefusalChirho
{
    fn from(error_chirho: ResidentGd7HeldAdoptionMaterializationRefusalChirho) -> Self {
        Self::AdoptionMaterializationChirho(error_chirho)
    }
}

impl From<ResidentGd7HeldAdoptionCommitRefusalChirho> for ResidentGd7HeldCoordinatorRefusalChirho {
    fn from(error_chirho: ResidentGd7HeldAdoptionCommitRefusalChirho) -> Self {
        Self::AdoptionCommitChirho(error_chirho)
    }
}

impl From<ResidentGd7HeldObligationMintRefusalChirho> for ResidentGd7HeldCoordinatorRefusalChirho {
    fn from(error_chirho: ResidentGd7HeldObligationMintRefusalChirho) -> Self {
        Self::ObligationMintChirho(error_chirho)
    }
}

/// Reopen a held node's existing signed checkpoint and losing journal behind one bounded actor.
///
/// `elector_chirho` must be the same instance whose transport owns the sole election ticker. This
/// function neither creates election state nor starts another clock.
pub fn open_resident_gd7_held_coordinator_chirho(
    selected_root_chirho: &Path,
    config_path_chirho: &Path,
    config_chirho: &LedgerHostConfigChirho,
    elector_chirho: Arc<RaftWriterElectorChirho>,
) -> Result<ResidentGd7HeldCoordinatorHandleChirho> {
    config_chirho.validate_chirho()?;
    verify_host_ledger_config_custody_chirho(selected_root_chirho, config_path_chirho)?;
    let selected_root_chirho = selected_root_chirho.to_path_buf();
    let config_path_chirho = config_path_chirho.to_path_buf();
    let config_chirho = config_chirho.clone();
    let (command_sender_chirho, command_receiver_chirho) =
        open_resident_gd7_held_coordinator_mailbox_chirho();
    let (startup_sender_chirho, startup_receiver_chirho) =
        sync_channel::<std::result::Result<(), String>>(1);
    let actor_thread_chirho = std::thread::Builder::new()
        .name("resident-gd7-held-coordinator-chirho".to_owned())
        .spawn(move || {
            let result_chirho = run_resident_gd7_held_coordinator_chirho(
                selected_root_chirho,
                config_path_chirho,
                config_chirho,
                elector_chirho,
                command_receiver_chirho,
                &startup_sender_chirho,
            );
            if let Err(error_chirho) = result_chirho {
                let _startup_result_chirho =
                    startup_sender_chirho.try_send(Err(error_chirho.to_string()));
            }
        })
        .context("spawn held GD7 coordinator actor")?;
    match startup_receiver_chirho.recv() {
        Ok(Ok(())) => Ok(ResidentGd7HeldCoordinatorHandleChirho::new_chirho(
            command_sender_chirho,
            actor_thread_chirho,
        )),
        Ok(Err(detail_chirho)) => {
            drop(command_sender_chirho);
            let _join_result_chirho = actor_thread_chirho.join();
            bail!("held GD7 coordinator refused startup: {detail_chirho}");
        }
        Err(_error_chirho) => {
            drop(command_sender_chirho);
            let _join_result_chirho = actor_thread_chirho.join();
            bail!("held GD7 coordinator stopped during startup");
        }
    }
}

fn run_resident_gd7_held_coordinator_chirho(
    selected_root_chirho: PathBuf,
    config_path_chirho: PathBuf,
    config_chirho: LedgerHostConfigChirho,
    elector_chirho: Arc<RaftWriterElectorChirho>,
    command_receiver_chirho: ResidentGd7HeldCoordinatorCommandReceiverChirho,
    startup_sender_chirho: &SyncSender<std::result::Result<(), String>>,
) -> Result<()> {
    config_chirho.validate_chirho()?;
    verify_host_ledger_config_custody_chirho(&selected_root_chirho, &config_path_chirho)?;
    let canonical_root_chirho = selected_root_chirho.canonicalize()?;
    let group_chirho = consistency_group_for_root_chirho(&canonical_root_chirho)?;
    let group_digest_chirho = consistency_group_digest_chirho(&group_chirho)?;
    let local_node_chirho = NodeIdChirho(
        cairn_signer_chirho::signer_chirho::existing_pubkey_hex_chirho(&canonical_root_chirho)?,
    );
    if elector_chirho.node_id_chirho() != &local_node_chirho {
        bail!("held GD7 coordinator elector node differs from the selected root");
    }

    let storage_namespace_chirho =
        canonical_root_chirho.join(&config_chirho.storage_namespace_chirho);
    let storage_chirho = FsLedgerStorageChirho::open_existing_chirho(&storage_namespace_chirho)?;
    let authority_storage_chirho =
        FsLedgerStorageChirho::open_existing_chirho(&canonical_root_chirho)?;
    let canary_root_chirho = canonical_root_chirho
        .join(&config_chirho.monitor_evidence_namespace_chirho)
        .join(RESIDENT_EFFECT_JOURNAL_CANARY_DIR_CHIRHO);
    let journal_path_chirho = StoragePathChirho::new_chirho(&config_chirho.journal_path_chirho);
    let cluster_id_chirho = ClusterIdChirho(config_chirho.cluster_id_chirho.clone());
    let held_losing_identity_chirho = HeldLosingJournalIdentityChirho::open_chirho(
        &canonical_root_chirho,
        &group_chirho,
        &local_node_chirho,
        &storage_chirho,
        &authority_storage_chirho,
        &canary_root_chirho,
        journal_path_chirho.clone(),
        cluster_id_chirho.clone(),
    )?;
    let writer_lock_path_chirho =
        StoragePathChirho::new_chirho(named_lock_storage_key_chirho(WRITER_FENCE_LOCK_CHIRHO));
    let mut writer_lock_handle_chirho = authority_storage_chirho
        .open_existing_exclusive_lock_handle_chirho(&writer_lock_path_chirho)
        .context("open held GD7 writer lock")?;
    let writer_lock_guard_chirho = writer_lock_handle_chirho
        .try_acquire_chirho()
        .context("acquire held GD7 writer lock")?;
    writer_lock_guard_chirho
        .verify_custody_chirho()
        .context("verify held GD7 writer-lock custody")?;
    let held_verifier_pins_chirho = config_chirho
        .held_verifier_pins_chirho
        .as_ref()
        .ok_or_else(|| anyhow!("held GD7 coordinator requires public ledger verifier pins"))?;
    let held_ledger_verifiers_chirho = HostLedgerHeldVerifiersChirho::from_config_chirho(
        &config_chirho.signer_secrets_chirho,
        held_verifier_pins_chirho,
    )?;
    held_ledger_verifiers_chirho.verify_control_key_separation_chirho(&local_node_chirho.0)?;
    let held_verifier_chirho = PinnedNodeGd7VerifierChirho::new_chirho(local_node_chirho.clone())?;
    let no_admission_registry_chirho = HeldReadOnlyKindRegistryChirho;
    let no_membership_chirho = HeldReadOnlyMembershipChirho;
    let no_authority_chirho = HeldReadOnlyAuthorityVerifierChirho;
    let clock_chirho = ResidentLedgerClockChirho::system_chirho();
    let losing_custody_chirho = held_losing_identity_chirho.freeze_chirho(
        JournalPortsChirho {
            storage_chirho: &storage_chirho,
            signer_chirho: &held_ledger_verifiers_chirho.journal_chirho,
            clock_chirho: &clock_chirho,
            membership_chirho: &no_membership_chirho,
            kind_registry_chirho: &no_admission_registry_chirho,
            authority_chirho: &no_authority_chirho,
        },
        &writer_lock_guard_chirho,
    )?;
    let losing_tail_chirho = losing_custody_chirho.losing_tail_chirho();
    let active_chirho = load_authenticated_active_gd7_reconciliation_for_group_chirho(
        &authority_storage_chirho,
        &held_verifier_chirho,
        &group_digest_chirho,
    )?;
    let live_reconciliation_chirho =
        config_chirho.schema_chirho == LEDGER_HOST_CONFIG_SCHEMA_V4_CHIRHO;
    let held_signer_chirho = live_reconciliation_chirho
        .then(|| {
            ExistingNodeGd7SignerChirho::open_existing_chirho(
                &canonical_root_chirho,
                &local_node_chirho,
            )
        })
        .transpose()?;
    let adoption_actor_ports_chirho = ResidentGd7HeldAdoptionActorPortsChirho {
        authority_storage_chirho: &authority_storage_chirho,
        candidate_storage_chirho: &storage_chirho,
        held_verifier_chirho: &held_verifier_chirho,
        held_signer_chirho: held_signer_chirho.as_ref(),
        held_ledger_verifiers_chirho: &held_ledger_verifiers_chirho,
        elector_chirho: elector_chirho.as_ref(),
        group_chirho: &group_chirho,
        group_digest_chirho: &group_digest_chirho,
        local_node_chirho: &local_node_chirho,
        losing_tail_chirho: &losing_tail_chirho,
        clock_chirho: &clock_chirho,
        membership_chirho: &no_membership_chirho,
        kind_registry_chirho: &no_admission_registry_chirho,
        authority_chirho: &no_authority_chirho,
        cluster_id_chirho: &cluster_id_chirho,
    };
    let mut identity_chirho = active_chirho
        .as_ref()
        .map(|active_chirho| active_chirho.checkpoint_chirho.identity_chirho.clone());
    if !live_reconciliation_chirho && identity_chirho.is_none() {
        bail!("held GD7 coordinator schema v3 requires an existing active checkpoint");
    }
    if let Some(active_identity_chirho) = identity_chirho.as_ref() {
        held_ledger_verifiers_chirho
            .verify_control_key_separation_chirho(&active_identity_chirho.winner_node_chirho)?;
        inspect_held_bootstrap_chirho(
            &authority_storage_chirho,
            &held_verifier_chirho,
            elector_chirho.as_ref(),
            &group_chirho,
            &group_digest_chirho,
            &local_node_chirho,
            Some(active_identity_chirho),
            &losing_tail_chirho,
            verify_held_read_only_election_observation_chirho,
        )
        .map_err(|error_chirho| anyhow!(error_chirho))?;
        if active_chirho.as_ref().is_some_and(|active_chirho| {
            active_chirho.checkpoint_chirho.state_chirho.phase_chirho
                == Gd7ReconciliationPhaseChirho::AdoptedHeldChirho
        }) {
            let active_chirho = active_chirho
                .as_ref()
                .ok_or_else(|| anyhow!("adopted held GD7 checkpoint disappeared"))?;
            verify_actor_owned_gd7_held_adoption_startup_chirho(
                active_identity_chirho,
                active_chirho,
                &adoption_actor_ports_chirho,
            )?;
        }
    } else if elector_chirho.node_id_chirho() != &local_node_chirho
        || elector_chirho
            .leadership_chirho(&group_chirho)
            .is_leader_chirho
    {
        bail!("held GD7 bootstrap elector does not remain bound as a nonleader");
    }
    writer_lock_guard_chirho
        .verify_custody_chirho()
        .context("reverify held GD7 writer-lock custody after startup")?;
    startup_sender_chirho
        .send(Ok(()))
        .map_err(|_error_chirho| anyhow!("held GD7 coordinator startup receiver closed"))?;

    while let Ok(command_chirho) = command_receiver_chirho.recv() {
        match command_chirho {
            ResidentGd7HeldCoordinatorCommandChirho::BootstrapChirho { reply_chirho } => {
                let result_chirho = (|| {
                    verify_held_runtime_custody_chirho(
                        &writer_lock_guard_chirho,
                        &losing_custody_chirho,
                        &losing_tail_chirho,
                    )?;
                    let snapshot_chirho = inspect_held_bootstrap_chirho(
                        &authority_storage_chirho,
                        &held_verifier_chirho,
                        elector_chirho.as_ref(),
                        &group_chirho,
                        &group_digest_chirho,
                        &local_node_chirho,
                        identity_chirho.as_ref(),
                        &losing_tail_chirho,
                        verify_held_read_only_election_observation_chirho,
                    )?;
                    verify_held_runtime_custody_chirho(
                        &writer_lock_guard_chirho,
                        &losing_custody_chirho,
                        &losing_tail_chirho,
                    )?;
                    Ok(snapshot_chirho)
                })();
                let _reply_result_chirho = reply_chirho.send(result_chirho);
            }
            ResidentGd7HeldCoordinatorCommandChirho::InspectChirho { reply_chirho } => {
                let result_chirho = (|| {
                    verify_held_runtime_custody_chirho(
                        &writer_lock_guard_chirho,
                        &losing_custody_chirho,
                        &losing_tail_chirho,
                    )?;
                    let expected_identity_chirho = identity_chirho
                        .as_ref()
                        .ok_or(ResidentGd7HeldCoordinatorRefusalChirho::CheckpointChirho)?;
                    let snapshot_chirho = inspect_held_coordinate_chirho(
                        &authority_storage_chirho,
                        &held_verifier_chirho,
                        elector_chirho.as_ref(),
                        &group_chirho,
                        &group_digest_chirho,
                        &local_node_chirho,
                        expected_identity_chirho,
                        &losing_tail_chirho,
                        verify_held_read_only_election_observation_chirho,
                    )?;
                    verify_held_runtime_custody_chirho(
                        &writer_lock_guard_chirho,
                        &losing_custody_chirho,
                        &losing_tail_chirho,
                    )?;
                    Ok(snapshot_chirho)
                })();
                let _reply_result_chirho = reply_chirho.send(result_chirho);
            }
            ResidentGd7HeldCoordinatorCommandChirho::InstallObservationChirho {
                import_chirho,
                reply_chirho,
            } => {
                let result_chirho = (|| {
                    verify_held_runtime_custody_chirho(
                        &writer_lock_guard_chirho,
                        &losing_custody_chirho,
                        &losing_tail_chirho,
                    )?;
                    let before_chirho = inspect_held_bootstrap_chirho(
                        &authority_storage_chirho,
                        &held_verifier_chirho,
                        elector_chirho.as_ref(),
                        &group_chirho,
                        &group_digest_chirho,
                        &local_node_chirho,
                        identity_chirho.as_ref(),
                        &losing_tail_chirho,
                        verify_held_historical_mutation_election_chirho,
                    )?;
                    let held_signer_chirho = held_signer_chirho.as_ref().ok_or(
                        ResidentGd7HeldCoordinatorRefusalChirho::LiveReconciliationNotConfiguredChirho,
                    )?;
                    held_ledger_verifiers_chirho
                        .verify_control_key_separation_chirho(&before_chirho.winner_node_chirho)
                        .map_err(|_error_chirho| {
                            ResidentGd7HeldCoordinatorRefusalChirho::ObservationChirho
                        })?;
                    validate_observation_identity_chirho(
                        &import_chirho.identity_chirho,
                        &before_chirho,
                    )?;
                    let winner_verifier_chirho = PinnedNodeGd7VerifierChirho::new_chirho(
                        NodeIdChirho(import_chirho.identity_chirho.winner_node_chirho.clone()),
                    )
                    .map_err(|_error_chirho| {
                        ResidentGd7HeldCoordinatorRefusalChirho::ObservationChirho
                    })?;
                    let witness_reader_chirho = Gd7WinnerWitnessReaderChirho::new_chirho(
                        &authority_storage_chirho,
                        &winner_verifier_chirho,
                        &held_ledger_verifiers_chirho.journal_chirho,
                    );
                    let observation_chirho = witness_reader_chirho
                        .import_authenticated_deposed_fork_observation_chirho(
                            &import_chirho.identity_chirho,
                            &import_chirho.winner_first_record_index_bytes_chirho,
                            &import_chirho.winner_fork_witness_bytes_chirho,
                            &losing_tail_chirho,
                        )
                        .map_err(|_error_chirho| {
                            ResidentGd7HeldCoordinatorRefusalChirho::ObservationChirho
                        })?;
                    let after_evidence_chirho = inspect_held_bootstrap_chirho(
                        &authority_storage_chirho,
                        &held_verifier_chirho,
                        elector_chirho.as_ref(),
                        &group_chirho,
                        &group_digest_chirho,
                        &local_node_chirho,
                        identity_chirho.as_ref(),
                        &losing_tail_chirho,
                        verify_held_historical_mutation_election_chirho,
                    )?;
                    if after_evidence_chirho != before_chirho {
                        return Err(
                            ResidentGd7HeldCoordinatorRefusalChirho::BootstrapSnapshotChangedChirho,
                        );
                    }
                    ensure_authenticated_deposed_fork_observed_held_chirho(
                        &authority_storage_chirho,
                        held_signer_chirho,
                        &observation_chirho,
                    )
                    .map_err(|_error_chirho| {
                        ResidentGd7HeldCoordinatorRefusalChirho::ObservationChirho
                    })?;
                    let installed_identity_chirho = import_chirho.identity_chirho.clone();
                    let snapshot_chirho = inspect_held_coordinate_chirho(
                        &authority_storage_chirho,
                        &held_verifier_chirho,
                        elector_chirho.as_ref(),
                        &group_chirho,
                        &group_digest_chirho,
                        &local_node_chirho,
                        &installed_identity_chirho,
                        &losing_tail_chirho,
                        verify_held_historical_mutation_election_chirho,
                    )?;
                    verify_held_runtime_custody_chirho(
                        &writer_lock_guard_chirho,
                        &losing_custody_chirho,
                        &losing_tail_chirho,
                    )?;
                    identity_chirho = Some(installed_identity_chirho);
                    Ok(snapshot_chirho)
                })();
                let _reply_result_chirho = reply_chirho.send(result_chirho);
            }
            ResidentGd7HeldCoordinatorCommandChirho::AdvanceOnePageChirho {
                expected_checkpoint_ref_chirho,
                reply_chirho,
            } => {
                let result_chirho = (|| {
                    let expected_identity_chirho = identity_chirho
                        .as_ref()
                        .ok_or(ResidentGd7HeldCoordinatorRefusalChirho::CheckpointChirho)?;
                    verify_held_runtime_custody_chirho(
                        &writer_lock_guard_chirho,
                        &losing_custody_chirho,
                        &losing_tail_chirho,
                    )?;
                    inspect_held_coordinate_chirho(
                        &authority_storage_chirho,
                        &held_verifier_chirho,
                        elector_chirho.as_ref(),
                        &group_chirho,
                        &group_digest_chirho,
                        &local_node_chirho,
                        expected_identity_chirho,
                        &losing_tail_chirho,
                        verify_held_historical_mutation_election_chirho,
                    )?;
                    let held_signer_chirho = held_signer_chirho.as_ref().ok_or(
                        ResidentGd7HeldCoordinatorRefusalChirho::LiveReconciliationNotConfiguredChirho,
                    )?;
                    let active_chirho = load_exact_held_active_chirho(
                        &authority_storage_chirho,
                        &held_verifier_chirho,
                        &group_digest_chirho,
                        expected_identity_chirho,
                        &expected_checkpoint_ref_chirho,
                    )?;
                    let observation_chirho = load_held_observation_chirho(
                        &authority_storage_chirho,
                        &held_ledger_verifiers_chirho,
                        expected_identity_chirho,
                        &losing_tail_chirho,
                    )?;
                    drive_one_held_page_chirho(
                        &authority_storage_chirho,
                        &canonical_root_chirho,
                        held_signer_chirho,
                        &held_ledger_verifiers_chirho,
                        losing_custody_chirho.reader_chirho(),
                        &observation_chirho,
                        &active_chirho,
                    )?;
                    let snapshot_chirho = inspect_held_coordinate_chirho(
                        &authority_storage_chirho,
                        &held_verifier_chirho,
                        elector_chirho.as_ref(),
                        &group_chirho,
                        &group_digest_chirho,
                        &local_node_chirho,
                        expected_identity_chirho,
                        &losing_tail_chirho,
                        verify_held_historical_mutation_election_chirho,
                    )?;
                    verify_held_runtime_custody_chirho(
                        &writer_lock_guard_chirho,
                        &losing_custody_chirho,
                        &losing_tail_chirho,
                    )?;
                    Ok(snapshot_chirho)
                })();
                let _reply_result_chirho = reply_chirho.send(result_chirho);
            }
            ResidentGd7HeldCoordinatorCommandChirho::VerifySealedPlanChirho {
                expected_checkpoint_ref_chirho,
                reply_chirho,
            } => {
                let result_chirho = (|| {
                    let expected_identity_chirho = identity_chirho
                        .as_ref()
                        .ok_or(ResidentGd7HeldCoordinatorRefusalChirho::CheckpointChirho)?;
                    verify_held_runtime_custody_chirho(
                        &writer_lock_guard_chirho,
                        &losing_custody_chirho,
                        &losing_tail_chirho,
                    )?;
                    inspect_held_coordinate_chirho(
                        &authority_storage_chirho,
                        &held_verifier_chirho,
                        elector_chirho.as_ref(),
                        &group_chirho,
                        &group_digest_chirho,
                        &local_node_chirho,
                        expected_identity_chirho,
                        &losing_tail_chirho,
                        verify_held_historical_mutation_election_chirho,
                    )?;
                    let held_signer_chirho = held_signer_chirho.as_ref().ok_or(
                        ResidentGd7HeldCoordinatorRefusalChirho::LiveReconciliationNotConfiguredChirho,
                    )?;
                    load_exact_held_active_chirho(
                        &authority_storage_chirho,
                        &held_verifier_chirho,
                        &group_digest_chirho,
                        expected_identity_chirho,
                        &expected_checkpoint_ref_chirho,
                    )?;
                    let observation_chirho = load_held_observation_chirho(
                        &authority_storage_chirho,
                        &held_ledger_verifiers_chirho,
                        expected_identity_chirho,
                        &losing_tail_chirho,
                    )?;
                    let proof_chirho = held_plan_ports_chirho(
                        &authority_storage_chirho,
                        &canonical_root_chirho,
                        held_signer_chirho,
                        &held_ledger_verifiers_chirho,
                    )?
                    .verify_sealed_chirho(&observation_chirho, &expected_checkpoint_ref_chirho)
                    .map_err(|_error_chirho| {
                        ResidentGd7HeldCoordinatorRefusalChirho::SealedPlanChirho
                    })?;
                    inspect_held_coordinate_chirho(
                        &authority_storage_chirho,
                        &held_verifier_chirho,
                        elector_chirho.as_ref(),
                        &group_chirho,
                        &group_digest_chirho,
                        &local_node_chirho,
                        expected_identity_chirho,
                        &losing_tail_chirho,
                        verify_held_historical_mutation_election_chirho,
                    )?;
                    verify_held_runtime_custody_chirho(
                        &writer_lock_guard_chirho,
                        &losing_custody_chirho,
                        &losing_tail_chirho,
                    )?;
                    Ok(sealed_plan_snapshot_chirho(&proof_chirho))
                })();
                let _reply_result_chirho = reply_chirho.send(result_chirho);
            }
            ResidentGd7HeldCoordinatorCommandChirho::PrepareAdoptionMaterializationChirho {
                request_chirho,
                reply_chirho,
            } => {
                let result_chirho = (|| {
                    let expected_identity_chirho = identity_chirho
                        .as_ref()
                        .ok_or(ResidentGd7HeldCoordinatorRefusalChirho::CheckpointChirho)?;
                    let transfer_identity_chirho = &request_chirho.transfer_identity_chirho;
                    if transfer_identity_chirho.reconciliation_identity_chirho
                        != *expected_identity_chirho
                        || transfer_identity_chirho
                            .reconciliation_checkpoint_ref_chirho
                            .is_empty()
                    {
                        return Err(
                            ResidentGd7HeldAdoptionMaterializationRefusalChirho::InvalidInputBindingChirho
                                .into(),
                        );
                    }
                    verify_held_runtime_custody_chirho(
                        &writer_lock_guard_chirho,
                        &losing_custody_chirho,
                        &losing_tail_chirho,
                    )?;
                    inspect_held_coordinate_chirho(
                        &authority_storage_chirho,
                        &held_verifier_chirho,
                        elector_chirho.as_ref(),
                        &group_chirho,
                        &group_digest_chirho,
                        &local_node_chirho,
                        expected_identity_chirho,
                        &losing_tail_chirho,
                        verify_held_historical_mutation_election_chirho,
                    )?;
                    let held_signer_chirho = held_signer_chirho.as_ref().ok_or(
                        ResidentGd7HeldCoordinatorRefusalChirho::LiveReconciliationNotConfiguredChirho,
                    )?;
                    let active_plan_chirho = load_exact_held_active_chirho(
                        &authority_storage_chirho,
                        &held_verifier_chirho,
                        &group_digest_chirho,
                        expected_identity_chirho,
                        &transfer_identity_chirho.reconciliation_checkpoint_ref_chirho,
                    )?;
                    if active_plan_chirho
                        .checkpoint_chirho
                        .state_chirho
                        .phase_chirho
                        != Gd7ReconciliationPhaseChirho::PlanSealedChirho
                    {
                        return Err(ResidentGd7HeldCoordinatorRefusalChirho::SealedPlanChirho);
                    }
                    let observation_chirho = load_held_observation_chirho(
                        &authority_storage_chirho,
                        &held_ledger_verifiers_chirho,
                        expected_identity_chirho,
                        &losing_tail_chirho,
                    )?;
                    let sealed_plan_chirho = held_plan_ports_chirho(
                        &authority_storage_chirho,
                        &canonical_root_chirho,
                        held_signer_chirho,
                        &held_ledger_verifiers_chirho,
                    )?
                    .verify_sealed_chirho(
                        &observation_chirho,
                        &transfer_identity_chirho.reconciliation_checkpoint_ref_chirho,
                    )
                    .map_err(|_error_chirho| {
                        ResidentGd7HeldCoordinatorRefusalChirho::SealedPlanChirho
                    })?;
                    let sealed_plan_snapshot_chirho =
                        sealed_plan_snapshot_chirho(&sealed_plan_chirho);
                    let winner_node_chirho =
                        NodeIdChirho(expected_identity_chirho.winner_node_chirho.clone());
                    let winner_verifier_chirho = PinnedNodeGd7VerifierChirho::new_chirho(
                        winner_node_chirho.clone(),
                    )
                    .map_err(|_error_chirho| {
                        ResidentGd7HeldAdoptionMaterializationRefusalChirho::InvalidInputBindingChirho
                    })?;
                    let evidence_store_chirho = Gd7HeldEvidenceTransferStoreChirho::new_chirho(
                        &authority_storage_chirho,
                        held_signer_chirho,
                        &winner_verifier_chirho,
                        &held_ledger_verifiers_chirho.journal_chirho,
                        transfer_identity_chirho.clone(),
                    )
                    .map_err(ResidentGd7HeldAdoptionMaterializationRefusalChirho::from)?;
                    let active_evidence_chirho = evidence_store_chirho
                        .load_active_chirho()
                        .map_err(ResidentGd7HeldAdoptionMaterializationRefusalChirho::from)?
                        .ok_or(
                            ResidentGd7HeldAdoptionMaterializationRefusalChirho::IncompleteEvidenceChirho,
                        )?;
                    if active_evidence_chirho.checkpoint_ref_chirho
                        != request_chirho.expected_evidence_checkpoint_ref_chirho
                        || active_evidence_chirho.checkpoint_chirho.phase_chirho
                            != Gd7HeldEvidenceTransferPhaseChirho::CompleteChirho
                    {
                        return Err(
                            ResidentGd7HeldAdoptionMaterializationRefusalChirho::StaleEvidenceChirho
                                .into(),
                        );
                    }
                    let active_branch_chirho = match evidence_store_chirho
                        .load_active_read_only_branch_evidence_chirho()
                        .map_err(ResidentGd7HeldAdoptionMaterializationRefusalChirho::from)?
                    {
                        Some(active_branch_chirho) => active_branch_chirho,
                        None => evidence_store_chirho
                            .prepare_and_install_read_only_branch_evidence_chirho(
                                losing_custody_chirho.reader_chirho(),
                                losing_custody_chirho.expected_genesis_chirho(),
                            )
                            .map_err(ResidentGd7HeldAdoptionMaterializationRefusalChirho::from)?,
                    };
                    if active_branch_chirho
                        .checkpoint_chirho
                        .transfer_identity_chirho
                        != *transfer_identity_chirho
                        || active_branch_chirho
                            .checkpoint_chirho
                            .evidence_checkpoint_ref_chirho
                            != request_chirho.expected_evidence_checkpoint_ref_chirho
                        || active_branch_chirho
                            .checkpoint_chirho
                            .held_view_checkpoint_ref_chirho
                            != transfer_identity_chirho.held_view_transfer_checkpoint_ref_chirho
                    {
                        return Err(
                            ResidentGd7HeldAdoptionMaterializationRefusalChirho::InvalidInputBindingChirho
                                .into(),
                        );
                    }
                    let prepared_chirho = materialize_gd7_held_adoption_candidate_chirho(
                        &evidence_store_chirho,
                        &sealed_plan_snapshot_chirho,
                        &request_chirho.expected_evidence_checkpoint_ref_chirho,
                        &active_branch_chirho.checkpoint_ref_chirho,
                        Gd7HeldAdoptionMaterializationPortsChirho {
                            candidate_storage_chirho: &storage_chirho,
                            winner_ledger_verifier_chirho: &held_ledger_verifiers_chirho
                                .journal_chirho,
                            clock_chirho: &clock_chirho,
                            membership_chirho: &no_membership_chirho,
                            kind_registry_chirho: &no_admission_registry_chirho,
                            authority_chirho: &no_authority_chirho,
                            cluster_id_chirho: &cluster_id_chirho,
                        },
                    )?;
                    let stable_plan_chirho = load_exact_held_active_chirho(
                        &authority_storage_chirho,
                        &held_verifier_chirho,
                        &group_digest_chirho,
                        expected_identity_chirho,
                        &sealed_plan_snapshot_chirho.checkpoint_ref_chirho,
                    )?;
                    if stable_plan_chirho != active_plan_chirho {
                        return Err(
                            ResidentGd7HeldAdoptionMaterializationRefusalChirho::StaleEvidenceChirho
                                .into(),
                        );
                    }
                    inspect_held_coordinate_chirho(
                        &authority_storage_chirho,
                        &held_verifier_chirho,
                        elector_chirho.as_ref(),
                        &group_chirho,
                        &group_digest_chirho,
                        &local_node_chirho,
                        expected_identity_chirho,
                        &losing_tail_chirho,
                        verify_held_historical_mutation_election_chirho,
                    )?;
                    verify_held_runtime_custody_chirho(
                        &writer_lock_guard_chirho,
                        &losing_custody_chirho,
                        &losing_tail_chirho,
                    )?;
                    Ok(prepared_chirho)
                })();
                let _reply_result_chirho = reply_chirho.send(result_chirho);
            }
            ResidentGd7HeldCoordinatorCommandChirho::CommitAdoptionChirho {
                prepared_chirho,
                reply_chirho,
            } => {
                let result_chirho = (|| {
                    let expected_identity_chirho = identity_chirho
                        .as_ref()
                        .ok_or(ResidentGd7HeldCoordinatorRefusalChirho::CheckpointChirho)?;
                    verify_held_runtime_custody_chirho(
                        &writer_lock_guard_chirho,
                        &losing_custody_chirho,
                        &losing_tail_chirho,
                    )?;
                    let outcome_chirho = commit_or_reload_actor_owned_gd7_held_adoption_chirho(
                        expected_identity_chirho,
                        &prepared_chirho,
                        &adoption_actor_ports_chirho,
                    )?;
                    verify_held_runtime_custody_chirho(
                        &writer_lock_guard_chirho,
                        &losing_custody_chirho,
                        &losing_tail_chirho,
                    )?;
                    Ok(outcome_chirho)
                })();
                let _reply_result_chirho = reply_chirho.send(result_chirho);
            }
            ResidentGd7HeldCoordinatorCommandChirho::MintLosingEffectObligationChirho {
                selector_chirho,
                reply_chirho,
            } => {
                let result_chirho = (|| {
                    // THE SUBJECT IS THE ACTOR'S OWN, AND THE REQUEST CANNOT REACH IT. The request
                    // carries a selector and nothing else, so "which obligation" is caller-chosen
                    // while "whose obligation" is not. That is the no-forged-subject rule made
                    // structural rather than validated: there is no caller-supplied identity to
                    // compare against, so there is no comparison to get wrong.
                    let expected_identity_chirho = identity_chirho
                        .as_ref()
                        .ok_or(ResidentGd7HeldCoordinatorRefusalChirho::CheckpointChirho)?;
                    verify_held_runtime_custody_chirho(
                        &writer_lock_guard_chirho,
                        &losing_custody_chirho,
                        &losing_tail_chirho,
                    )?;
                    // BUILT PER-COMMAND, FROM THE IDENTITY THIS ACTOR VERIFIED — never at actor
                    // open. The winner is a property of the identity, so a verifier built at open
                    // would be bound before the identity that justifies it exists, and would then
                    // outlive any identity change rather than being rebuilt against the current
                    // one. The mint re-checks this verifier's key id against the identity's winner
                    // node and refuses `InvalidWinnerControlVerifier` on mismatch, so deriving it
                    // from anything else here would simply refuse.
                    let winner_control_verifier_chirho =
                        PinnedNodeGd7VerifierChirho::new_from_key_id_chirho(
                            expected_identity_chirho.winner_node_chirho.clone(),
                        )
                        .map_err(|_error_chirho| {
                            ResidentGd7HeldCoordinatorRefusalChirho::ObligationMintChirho(
                                ResidentGd7HeldObligationMintRefusalChirho::InvalidWinnerControlVerifierChirho,
                            )
                        })?;
                    // The same `None` -> `LiveReconciliationNotConfigured` the plan ports already
                    // use, reused rather than reinvented: a v3 schema has no effect verifiers, and
                    // that is a configuration fact, not a mint verdict.
                    let intent_verifier_chirho = held_ledger_verifiers_chirho
                        .effect_intent_chirho
                        .as_ref()
                        .ok_or(
                        ResidentGd7HeldCoordinatorRefusalChirho::LiveReconciliationNotConfiguredChirho,
                    )?;
                    let terminal_verifier_chirho = held_ledger_verifiers_chirho
                        .effect_terminal_chirho
                        .as_ref()
                        .ok_or(
                        ResidentGd7HeldCoordinatorRefusalChirho::LiveReconciliationNotConfiguredChirho,
                    )?;
                    let evidence_reader_chirho =
                        RootGd7EffectEvidenceReaderChirho::new_chirho(&canonical_root_chirho);
                    let mint_ports_chirho = ResidentGd7HeldObligationMintActorPortsChirho {
                        authority_storage_chirho: &authority_storage_chirho,
                        candidate_storage_chirho: &storage_chirho,
                        held_verifier_chirho: &held_verifier_chirho,
                        held_signer_chirho: held_signer_chirho.as_ref().map(|signer_chirho| {
                            signer_chirho as &dyn Gd7ReconciliationSignerPortChirho
                        }),
                        winner_control_verifier_chirho: &winner_control_verifier_chirho,
                        winner_ledger_verifier_chirho: &held_ledger_verifiers_chirho.journal_chirho,
                        effect_proof_ports_chirho: Gd7EffectProofPortsChirho::new_chirho(
                            &evidence_reader_chirho,
                            intent_verifier_chirho,
                            terminal_verifier_chirho,
                        ),
                        clock_chirho: &clock_chirho,
                        membership_chirho: &no_membership_chirho,
                        kind_registry_chirho: &no_admission_registry_chirho,
                        authority_chirho: &no_authority_chirho,
                        cluster_id_chirho: &cluster_id_chirho,
                        group_digest_chirho: &group_digest_chirho,
                    };
                    // NO ADOPTION CAS CHECKS HERE. The mint owns its own before/after adoption
                    // snapshot comparison around the durable claim, so duplicating them at this
                    // boundary would widen the window rather than narrow it: an outer check would
                    // pass, the inner claim would happen, and the outer post-check would be a
                    // second opinion about a decision already made durably. This arm wraps custody
                    // only, exactly as its `CommitAdoption` sibling does.
                    let minted_chirho = mint_actor_owned_gd7_losing_effect_obligation_chirho(
                        expected_identity_chirho,
                        &selector_chirho,
                        &mint_ports_chirho,
                    )?;
                    verify_held_runtime_custody_chirho(
                        &writer_lock_guard_chirho,
                        &losing_custody_chirho,
                        &losing_tail_chirho,
                    )?;
                    Ok(minted_chirho)
                })();
                let _reply_result_chirho = reply_chirho.send(result_chirho);
            }
        }
    }
    Ok(())
}

fn verify_held_runtime_custody_chirho(
    writer_lock_guard_chirho: &StableLedgerExclusiveLockGuardChirho<'_>,
    losing_custody_chirho: &HeldLosingJournalCustodyChirho<'_>,
    expected_losing_tail_chirho: &VerifiedLosingJournalTailChirho,
) -> std::result::Result<(), ResidentGd7HeldCoordinatorRefusalChirho> {
    let current_losing_tail_chirho = losing_custody_chirho
        .verify_custody_chirho(writer_lock_guard_chirho)
        .map_err(|_error_chirho| {
            ResidentGd7HeldCoordinatorRefusalChirho::LosingJournalChangedChirho
        })?;
    if !same_losing_tail_chirho(expected_losing_tail_chirho, &current_losing_tail_chirho) {
        return Err(ResidentGd7HeldCoordinatorRefusalChirho::LosingJournalChangedChirho);
    }
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "bootstrap validates one explicit held authority tuple without ambient state"
)]
fn inspect_held_bootstrap_chirho(
    authority_storage_chirho: &FsLedgerStorageChirho,
    held_verifier_chirho: &PinnedNodeGd7VerifierChirho,
    elector_chirho: &RaftWriterElectorChirho,
    group_chirho: &ConsistencyGroupIdChirho,
    group_digest_chirho: &str,
    local_node_chirho: &NodeIdChirho,
    identity_chirho: Option<&Gd7ReconciliationIdentityChirho>,
    losing_tail_chirho: &VerifiedLosingJournalTailChirho,
    identity_election_verifier_chirho: HeldIdentityElectionVerifierChirho,
) -> std::result::Result<
    ResidentGd7HeldBootstrapSnapshotChirho,
    ResidentGd7HeldCoordinatorRefusalChirho,
> {
    let before_chirho = match identity_chirho {
        Some(identity_chirho) => identity_election_verifier_chirho(
            elector_chirho,
            group_chirho,
            identity_chirho,
            local_node_chirho,
        )?,
        None => verify_held_bootstrap_election_chirho(
            elector_chirho,
            group_chirho,
            local_node_chirho,
            losing_tail_chirho,
        )?,
    };
    let active_chirho = load_authenticated_active_gd7_reconciliation_for_group_chirho(
        authority_storage_chirho,
        held_verifier_chirho,
        group_digest_chirho,
    )
    .map_err(|_error_chirho| ResidentGd7HeldCoordinatorRefusalChirho::CheckpointChirho)?;
    let active_checkpoint_ref_chirho = match (identity_chirho, active_chirho.as_ref()) {
        (Some(identity_chirho), Some(active_chirho)) => {
            validate_held_coordinate_chirho(
                active_chirho,
                identity_chirho,
                group_digest_chirho,
                local_node_chirho,
                losing_tail_chirho,
            )?;
            Some(active_chirho.checkpoint_ref_chirho.clone())
        }
        (None, None) => None,
        _ => {
            return Err(ResidentGd7HeldCoordinatorRefusalChirho::CheckpointChangedIdentityChirho);
        }
    };
    let after_chirho = match identity_chirho {
        Some(identity_chirho) => identity_election_verifier_chirho(
            elector_chirho,
            group_chirho,
            identity_chirho,
            local_node_chirho,
        )?,
        None => verify_held_bootstrap_election_chirho(
            elector_chirho,
            group_chirho,
            local_node_chirho,
            losing_tail_chirho,
        )?,
    };
    require_stable_election_observation_chirho(&before_chirho, &after_chirho)?;
    let (winner_node_chirho, winner_term_chirho) = match identity_chirho {
        Some(identity_chirho) => (
            identity_chirho.winner_node_chirho.clone(),
            identity_chirho.winner_term_chirho,
        ),
        None => (
            before_chirho
                .leader_id_chirho
                .as_ref()
                .ok_or(ResidentGd7HeldCoordinatorRefusalChirho::NoElectedWinnerObservedChirho)?
                .0
                .clone(),
            before_chirho.term_chirho,
        ),
    };
    Ok(ResidentGd7HeldBootstrapSnapshotChirho {
        consistency_group_digest_chirho: group_digest_chirho.to_owned(),
        winner_node_chirho,
        held_node_chirho: local_node_chirho.0.clone(),
        winner_term_chirho,
        losing_journal_genesis_digest_chirho: losing_tail_chirho
            .identity_chirho()
            .genesis_digest_chirho()
            .0
            .clone(),
        losing_tail_epoch_chirho: losing_tail_chirho.record_epoch_chirho(),
        losing_tail_seq_chirho: losing_tail_chirho.coordinate_chirho().seq_chirho(),
        losing_tail_digest_chirho: losing_tail_chirho
            .coordinate_chirho()
            .record_digest_chirho()
            .0
            .clone(),
        active_checkpoint_ref_chirho,
    })
}

fn validate_observation_identity_chirho(
    identity_chirho: &Gd7ReconciliationIdentityChirho,
    bootstrap_chirho: &ResidentGd7HeldBootstrapSnapshotChirho,
) -> std::result::Result<(), ResidentGd7HeldCoordinatorRefusalChirho> {
    if identity_chirho.consistency_group_digest_chirho
        != bootstrap_chirho.consistency_group_digest_chirho
        || identity_chirho.winner_node_chirho != bootstrap_chirho.winner_node_chirho
        || identity_chirho.held_node_chirho != bootstrap_chirho.held_node_chirho
        || identity_chirho.winner_term_chirho != bootstrap_chirho.winner_term_chirho
        || identity_chirho.losing_journal_genesis_digest_chirho
            != bootstrap_chirho.losing_journal_genesis_digest_chirho
        || identity_chirho.losing_journal_tail_chirho.epoch_chirho
            != bootstrap_chirho.losing_tail_epoch_chirho
        || identity_chirho.losing_journal_tail_chirho.seq_chirho
            != bootstrap_chirho.losing_tail_seq_chirho
        || identity_chirho
            .losing_journal_tail_chirho
            .record_digest_chirho
            != bootstrap_chirho.losing_tail_digest_chirho
    {
        return Err(ResidentGd7HeldCoordinatorRefusalChirho::ObservationChirho);
    }
    Ok(())
}

fn same_losing_tail_chirho(
    expected_chirho: &VerifiedLosingJournalTailChirho,
    actual_chirho: &VerifiedLosingJournalTailChirho,
) -> bool {
    expected_chirho.identity_chirho() == actual_chirho.identity_chirho()
        && expected_chirho.record_epoch_chirho() == actual_chirho.record_epoch_chirho()
        && expected_chirho.coordinate_chirho() == actual_chirho.coordinate_chirho()
}

fn load_exact_held_active_chirho(
    authority_storage_chirho: &FsLedgerStorageChirho,
    held_verifier_chirho: &PinnedNodeGd7VerifierChirho,
    group_digest_chirho: &str,
    expected_identity_chirho: &Gd7ReconciliationIdentityChirho,
    expected_checkpoint_ref_chirho: &str,
) -> std::result::Result<ActiveGd7ReconciliationChirho, ResidentGd7HeldCoordinatorRefusalChirho> {
    let active_chirho = load_authenticated_active_gd7_reconciliation_for_group_chirho(
        authority_storage_chirho,
        held_verifier_chirho,
        group_digest_chirho,
    )
    .map_err(|_error_chirho| ResidentGd7HeldCoordinatorRefusalChirho::CheckpointChirho)?
    .ok_or(ResidentGd7HeldCoordinatorRefusalChirho::CheckpointChirho)?;
    if active_chirho.checkpoint_ref_chirho != expected_checkpoint_ref_chirho
        || active_chirho.checkpoint_chirho.identity_chirho != *expected_identity_chirho
    {
        return Err(ResidentGd7HeldCoordinatorRefusalChirho::CheckpointChangedIdentityChirho);
    }
    Ok(active_chirho)
}

fn load_held_observation_chirho(
    authority_storage_chirho: &FsLedgerStorageChirho,
    held_ledger_verifiers_chirho: &HostLedgerHeldVerifiersChirho,
    identity_chirho: &Gd7ReconciliationIdentityChirho,
    losing_tail_chirho: &VerifiedLosingJournalTailChirho,
) -> std::result::Result<
    AuthenticatedGd7DeposedForkObservationChirho,
    ResidentGd7HeldCoordinatorRefusalChirho,
> {
    let winner_verifier_chirho = PinnedNodeGd7VerifierChirho::new_chirho(NodeIdChirho(
        identity_chirho.winner_node_chirho.clone(),
    ))
    .map_err(|_error_chirho| ResidentGd7HeldCoordinatorRefusalChirho::ObservationChirho)?;
    Gd7WinnerWitnessReaderChirho::new_chirho(
        authority_storage_chirho,
        &winner_verifier_chirho,
        &held_ledger_verifiers_chirho.journal_chirho,
    )
    .load_authenticated_deposed_fork_observation_chirho(identity_chirho, losing_tail_chirho)
    .map_err(|_error_chirho| ResidentGd7HeldCoordinatorRefusalChirho::ObservationChirho)
}

fn held_plan_ports_chirho<'ports_chirho>(
    authority_storage_chirho: &'ports_chirho FsLedgerStorageChirho,
    canonical_root_chirho: &Path,
    held_signer_chirho: &'ports_chirho ExistingNodeGd7SignerChirho,
    held_ledger_verifiers_chirho: &'ports_chirho HostLedgerHeldVerifiersChirho,
) -> std::result::Result<
    ResidentGd7PlanPortsChirho<'ports_chirho>,
    ResidentGd7HeldCoordinatorRefusalChirho,
> {
    let intent_verifier_chirho = held_ledger_verifiers_chirho
        .effect_intent_chirho
        .as_ref()
        .ok_or(ResidentGd7HeldCoordinatorRefusalChirho::LiveReconciliationNotConfiguredChirho)?;
    let terminal_verifier_chirho = held_ledger_verifiers_chirho
        .effect_terminal_chirho
        .as_ref()
        .ok_or(ResidentGd7HeldCoordinatorRefusalChirho::LiveReconciliationNotConfiguredChirho)?;
    Ok(ResidentGd7PlanPortsChirho::new_chirho(
        authority_storage_chirho,
        canonical_root_chirho,
        held_signer_chirho,
        &held_ledger_verifiers_chirho.journal_chirho,
        intent_verifier_chirho,
        terminal_verifier_chirho,
        None,
    ))
}

#[allow(
    clippy::too_many_arguments,
    reason = "one bounded progression composes explicit immutable evidence ports"
)]
fn drive_one_held_page_chirho(
    authority_storage_chirho: &FsLedgerStorageChirho,
    canonical_root_chirho: &Path,
    held_signer_chirho: &ExistingNodeGd7SignerChirho,
    held_ledger_verifiers_chirho: &HostLedgerHeldVerifiersChirho,
    journal_chirho: &dyn LosingSuffixReaderChirho,
    observation_chirho: &AuthenticatedGd7DeposedForkObservationChirho,
    active_chirho: &ActiveGd7ReconciliationChirho,
) -> std::result::Result<(), ResidentGd7HeldCoordinatorRefusalChirho> {
    let state_chirho = &active_chirho.checkpoint_chirho.state_chirho;
    match state_chirho.phase_chirho {
        Gd7ReconciliationPhaseChirho::ObservedHeldChirho => {
            drive_authenticated_losing_manifest_page_chirho(
                authority_storage_chirho,
                held_signer_chirho,
                journal_chirho,
                observation_chirho,
                &active_chirho.checkpoint_ref_chirho,
                Gd7ManifestPageBudgetChirho::new_chirho(
                    MAX_LOSING_SUFFIX_PAGE_RECORDS_CHIRHO,
                    MAX_LOSING_SUFFIX_PAGE_BYTES_CHIRHO,
                ),
            )
            .map_err(|_error_chirho| ResidentGd7HeldCoordinatorRefusalChirho::ManifestChirho)?;
        }
        Gd7ReconciliationPhaseChirho::ManifestingChirho
            if state_chirho.plan_page_count_chirho < state_chirho.manifest_page_count_chirho =>
        {
            held_plan_ports_chirho(
                authority_storage_chirho,
                canonical_root_chirho,
                held_signer_chirho,
                held_ledger_verifiers_chirho,
            )?
            .drive_chirho(observation_chirho, &active_chirho.checkpoint_ref_chirho)
            .map_err(ResidentGd7HeldCoordinatorRefusalChirho::PlanChirho)?;
        }
        Gd7ReconciliationPhaseChirho::ManifestingChirho
            if state_chirho.plan_page_count_chirho == state_chirho.manifest_page_count_chirho
                && state_chirho.cursor_object_ref_chirho.is_some() =>
        {
            drive_authenticated_losing_manifest_page_chirho(
                authority_storage_chirho,
                held_signer_chirho,
                journal_chirho,
                observation_chirho,
                &active_chirho.checkpoint_ref_chirho,
                Gd7ManifestPageBudgetChirho::new_chirho(
                    MAX_LOSING_SUFFIX_PAGE_RECORDS_CHIRHO,
                    MAX_LOSING_SUFFIX_PAGE_BYTES_CHIRHO,
                ),
            )
            .map_err(|_error_chirho| ResidentGd7HeldCoordinatorRefusalChirho::ManifestChirho)?;
        }
        Gd7ReconciliationPhaseChirho::PlanSealedChirho => {}
        Gd7ReconciliationPhaseChirho::AdoptedHeldChirho => {
            return Err(
                ResidentGd7HeldCoordinatorRefusalChirho::UndrivablePhaseChirho(
                    Gd7ReconciliationPhaseChirho::AdoptedHeldChirho,
                ),
            );
        }
        Gd7ReconciliationPhaseChirho::ManifestingChirho => {
            return Err(
                ResidentGd7HeldCoordinatorRefusalChirho::UndrivablePhaseChirho(
                    Gd7ReconciliationPhaseChirho::ManifestingChirho,
                ),
            );
        }
    }
    Ok(())
}

fn sealed_plan_snapshot_chirho(
    proof_chirho: &VerifiedGd7SealedPlanProofChirho,
) -> ResidentGd7HeldSealedPlanSnapshotChirho {
    ResidentGd7HeldSealedPlanSnapshotChirho {
        reconciliation_identity_digest_chirho: proof_chirho
            .reconciliation_identity_digest_chirho()
            .to_owned(),
        checkpoint_ref_chirho: proof_chirho.checkpoint_ref_chirho().to_owned(),
        sealed_plan_ref_chirho: proof_chirho.sealed_plan_ref_chirho().to_owned(),
        winner_fork_witness_object_digest_chirho: proof_chirho
            .winner_fork_witness_object_digest_chirho()
            .to_owned(),
        winner_term_chirho: proof_chirho.winner_term_chirho(),
        plan_page_count_chirho: proof_chirho.plan_page_count_chirho(),
        manifest_record_count_chirho: proof_chirho.manifest_record_count_chirho(),
        effect_obligation_count_chirho: proof_chirho.effect_obligation_count_chirho(),
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "the held inspection rechecks one fixed authority tuple without ambient state"
)]
fn inspect_held_coordinate_chirho(
    authority_storage_chirho: &FsLedgerStorageChirho,
    held_verifier_chirho: &PinnedNodeGd7VerifierChirho,
    elector_chirho: &RaftWriterElectorChirho,
    group_chirho: &ConsistencyGroupIdChirho,
    group_digest_chirho: &str,
    local_node_chirho: &NodeIdChirho,
    identity_chirho: &Gd7ReconciliationIdentityChirho,
    losing_tail_chirho: &VerifiedLosingJournalTailChirho,
    identity_election_verifier_chirho: HeldIdentityElectionVerifierChirho,
) -> std::result::Result<
    ResidentGd7HeldCoordinatorSnapshotChirho,
    ResidentGd7HeldCoordinatorRefusalChirho,
> {
    let before_chirho = identity_election_verifier_chirho(
        elector_chirho,
        group_chirho,
        identity_chirho,
        local_node_chirho,
    )?;
    let active_chirho = load_authenticated_active_gd7_reconciliation_for_group_chirho(
        authority_storage_chirho,
        held_verifier_chirho,
        group_digest_chirho,
    )
    .map_err(|_error_chirho| ResidentGd7HeldCoordinatorRefusalChirho::CheckpointChirho)?
    .ok_or(ResidentGd7HeldCoordinatorRefusalChirho::CheckpointChirho)?;
    validate_held_coordinate_chirho(
        &active_chirho,
        identity_chirho,
        group_digest_chirho,
        local_node_chirho,
        losing_tail_chirho,
    )?;
    let after_chirho = identity_election_verifier_chirho(
        elector_chirho,
        group_chirho,
        identity_chirho,
        local_node_chirho,
    )?;
    require_stable_election_observation_chirho(&before_chirho, &after_chirho)?;
    Ok(snapshot_chirho(&active_chirho))
}

fn validate_held_coordinate_chirho(
    active_chirho: &ActiveGd7ReconciliationChirho,
    identity_chirho: &Gd7ReconciliationIdentityChirho,
    group_digest_chirho: &str,
    local_node_chirho: &NodeIdChirho,
    losing_tail_chirho: &VerifiedLosingJournalTailChirho,
) -> std::result::Result<(), ResidentGd7HeldCoordinatorRefusalChirho> {
    if active_chirho.checkpoint_chirho.identity_chirho != *identity_chirho
        || identity_chirho.consistency_group_digest_chirho != group_digest_chirho
        || identity_chirho.held_node_chirho != local_node_chirho.0
    {
        return Err(ResidentGd7HeldCoordinatorRefusalChirho::CheckpointChangedIdentityChirho);
    }
    if identity_chirho.losing_journal_genesis_digest_chirho
        != losing_tail_chirho
            .identity_chirho()
            .genesis_digest_chirho()
            .0
        || identity_chirho.losing_journal_tail_chirho.epoch_chirho
            != losing_tail_chirho.record_epoch_chirho()
        || identity_chirho.losing_journal_tail_chirho.seq_chirho
            != losing_tail_chirho.coordinate_chirho().seq_chirho()
        || identity_chirho
            .losing_journal_tail_chirho
            .record_digest_chirho
            != losing_tail_chirho
                .coordinate_chirho()
                .record_digest_chirho()
                .0
    {
        return Err(ResidentGd7HeldCoordinatorRefusalChirho::LosingJournalChangedChirho);
    }
    Ok(())
}

fn snapshot_chirho(
    active_chirho: &ActiveGd7ReconciliationChirho,
) -> ResidentGd7HeldCoordinatorSnapshotChirho {
    let checkpoint_chirho = &active_chirho.checkpoint_chirho;
    let identity_chirho = &checkpoint_chirho.identity_chirho;
    ResidentGd7HeldCoordinatorSnapshotChirho {
        checkpoint_ref_chirho: active_chirho.checkpoint_ref_chirho.clone(),
        phase_chirho: checkpoint_chirho.state_chirho.phase_chirho,
        transition_seq_chirho: checkpoint_chirho.state_chirho.transition_seq_chirho,
        consistency_group_digest_chirho: identity_chirho.consistency_group_digest_chirho.clone(),
        winner_node_chirho: identity_chirho.winner_node_chirho.clone(),
        held_node_chirho: identity_chirho.held_node_chirho.clone(),
        winner_term_chirho: identity_chirho.winner_term_chirho,
        losing_tail_epoch_chirho: identity_chirho.losing_journal_tail_chirho.epoch_chirho,
        losing_tail_seq_chirho: identity_chirho.losing_journal_tail_chirho.seq_chirho,
        losing_tail_digest_chirho: identity_chirho
            .losing_journal_tail_chirho
            .record_digest_chirho
            .clone(),
    }
}
