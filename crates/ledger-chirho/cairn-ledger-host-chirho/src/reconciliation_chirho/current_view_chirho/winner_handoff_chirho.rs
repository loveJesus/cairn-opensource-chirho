// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Winner-signed, restart-stable quiescence state for one GD7 held-view handoff.
//!
//! The fixed head makes restart recovery O(1). Immutable checkpoints preserve the exact challenge
//! and winner inspection that were sealed while local append authority was held. This store cannot
//! acquire authority, append, compensate, adopt a held view, move refs, or re-enable writes.

use super::super::{
    load_authenticated_gd7_reconciliation_checkpoint_by_ref_chirho,
    verify_and_retain_gd7_reconciliation_checkpoint_chirho, Gd7ReconciliationCheckpointChirho,
    Gd7ReconciliationPhaseChirho, Gd7ReconciliationStoreRefusalChirho,
};
use super::fork_baseline_chirho::stage_gd7_fork_baseline_chirho;
use super::winner_history_chirho::stage_next_gd7_winner_history_page_chirho;
use super::{
    build_gd7_winner_evidence_manifest_chirho, canonical_json_chirho,
    consistency_group_digest_suffix_chirho, digest_bytes_chirho,
    fetch_gd7_winner_evidence_page_chirho, is_lower_hex_digest_chirho,
    parse_canonical_gd7_winner_current_view_challenge_chirho, validate_key_and_signature_chirho,
    verify_complete_gd7_held_view_transfer_checkpoint_chirho,
    verify_inline_gd7_winner_current_view_inspection_chirho, Gd7ForkBaselineIdentityChirho,
    Gd7ForkBaselineRefusalChirho, Gd7HeldEvidenceTransferIdentityChirho,
    Gd7HeldViewTransferCheckpointChirho, Gd7HeldViewTransferIdentityChirho,
    Gd7HeldViewTransferStoreRefusalChirho, Gd7ReconciliationSignerPortChirho,
    Gd7ReconciliationVerifierPortChirho, Gd7WinnerCurrentViewInspectionChirho,
    Gd7WinnerEvidenceManifestChirho, Gd7WinnerEvidencePageGrantChirho,
    Gd7WinnerEvidencePageTransferChirho, Gd7WinnerEvidenceTransferRefusalChirho,
    Gd7WinnerHistoryIdentityChirho, Gd7WinnerHistoryRefusalChirho, Gd7WinnerHistoryRestartChirho,
    Gd7WinnerHistoryStageOutcomeChirho, VerifiedGd7ForkBaselineRootChirho,
    VerifiedGd7WinnerHistoryRootChirho,
};
use cairn_ledger_log_chirho::journal_chirho::JournalPortsChirho;
use cairn_ledger_log_chirho::losing_suffix_chirho::LosingSuffixReaderChirho;
use cairn_ledger_log_chirho::ports_chirho::{
    CreateDurableOutcomeChirho, LedgerStoragePortChirho, StoragePathChirho,
};
use cairn_ledger_model_chirho::ids_chirho::ClusterIdChirho;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt;

const GD7_RECONCILIATION_NAMESPACE_CHIRHO: &str = "gd7-reconciliation-chirho";
pub const GD7_WINNER_HANDOFF_CHECKPOINT_SCHEMA_V1_CHIRHO: &str =
    "gd7-winner-handoff-checkpoint-v1-chirho";
pub const GD7_WINNER_HANDOFF_HEAD_SCHEMA_V1_CHIRHO: &str = "gd7-winner-handoff-head-v1-chirho";
pub const MAX_GD7_WINNER_HANDOFF_CHECKPOINT_BYTES_CHIRHO: usize = 64 * 1024;
pub const MAX_GD7_WINNER_HANDOFF_HEAD_BYTES_CHIRHO: usize = 8 * 1024;

/// Stable identity available before the winner enters append quiescence.
///
/// The digest of this value is the process-local barrier identity. The durable checkpoint adds the
/// exact evidence generation, bundle root, and source cut produced while that barrier is prepared.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gd7WinnerHandoffAttemptIdentityChirho {
    pub held_transfer_identity_chirho: Gd7HeldViewTransferIdentityChirho,
    pub held_transfer_checkpoint_ref_chirho: String,
    pub expected_bundle_root_object_digest_chirho: String,
    pub challenge_digest_chirho: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants must carry the Chirho suffix"
)]
pub enum Gd7WinnerHandoffPhaseChirho {
    PreparingChirho,
    AcceptedChirho,
    AbortedChirho,
}

/// One immutable winner-signed transition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gd7WinnerHandoffCheckpointChirho {
    pub schema_chirho: String,
    pub attempt_identity_chirho: Gd7WinnerHandoffAttemptIdentityChirho,
    pub transition_seq_chirho: u64,
    pub previous_checkpoint_ref_chirho: Option<String>,
    pub phase_chirho: Gd7WinnerHandoffPhaseChirho,
    pub canonical_challenge_chirho: String,
    pub inspection_chirho: Gd7WinnerCurrentViewInspectionChirho,
    pub preparing_process_generation_chirho: u64,
    pub accepting_process_generation_chirho: Option<u64>,
    pub key_id_chirho: String,
    pub sig_chirho: String,
}

/// Fixed O(1)-addressed pointer to the latest durable handoff decision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gd7WinnerHandoffHeadChirho {
    pub schema_chirho: String,
    pub consistency_group_digest_chirho: String,
    pub winner_node_chirho: String,
    pub attempt_digest_chirho: String,
    pub active_checkpoint_ref_chirho: String,
    pub transition_seq_chirho: u64,
    pub phase_chirho: Gd7WinnerHandoffPhaseChirho,
    pub key_id_chirho: String,
    pub sig_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActiveGd7WinnerHandoffChirho {
    pub attempt_digest_chirho: String,
    pub checkpoint_ref_chirho: String,
    pub checkpoint_chirho: Gd7WinnerHandoffCheckpointChirho,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommittedGd7WinnerHandoffChirho {
    pub attempt_digest_chirho: String,
    pub checkpoint_ref_chirho: String,
    pub checkpoint_chirho: Gd7WinnerHandoffCheckpointChirho,
}

/// Result of installing one signed fixed-head transition.
///
/// `DurabilityUnconfirmedChirho` means the atomic replacement returned an error after the
/// immutable checkpoint was durable. The head may already name that checkpoint, so callers must
/// retain the append freeze and retry [`Gd7WinnerHandoffStoreChirho::confirm_active_chirho`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Gd7WinnerHandoffCommitOutcomeChirho {
    DurableChirho(CommittedGd7WinnerHandoffChirho),
    DurabilityUnconfirmedChirho(CommittedGd7WinnerHandoffChirho),
}

impl Gd7WinnerHandoffCommitOutcomeChirho {
    pub fn into_parts_chirho(self) -> (CommittedGd7WinnerHandoffChirho, bool) {
        match self {
            Self::DurableChirho(committed_chirho) => (committed_chirho, true),
            Self::DurabilityUnconfirmedChirho(committed_chirho) => (committed_chirho, false),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants must carry the Chirho suffix"
)]
pub enum Gd7WinnerHandoffStoreRefusalChirho {
    InvalidIdentityChirho,
    WrongWinnerSignerChirho,
    ActiveAttemptMismatchChirho,
    WrongExpectedPriorChirho,
    InvalidTransitionChirho,
    InvalidChallengeChirho,
    InvalidWinnerEvidenceChirho,
    MalformedHeadChirho,
    MalformedCheckpointChirho,
    NonCanonicalHeadChirho,
    NonCanonicalCheckpointChirho,
    OversizedHeadChirho,
    OversizedCheckpointChirho,
    InvalidHeadSignatureChirho,
    InvalidCheckpointSignatureChirho,
    MissingCheckpointChirho,
    DigestMismatchChirho,
    ImmutableCollisionChirho,
    PlanCheckpointChirho(Gd7ReconciliationStoreRefusalChirho),
    SerializationChirho,
    SigningChirho,
    ForkBaselineChirho(Gd7ForkBaselineRefusalChirho),
    WinnerHistoryChirho(Gd7WinnerHistoryRefusalChirho),
    EvidenceTransferChirho(Gd7WinnerEvidenceTransferRefusalChirho),
    StorageChirho,
}

impl fmt::Display for Gd7WinnerHandoffStoreRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter_chirho.write_str(match self {
            Self::InvalidIdentityChirho => "GD7 winner-handoff identity is invalid",
            Self::WrongWinnerSignerChirho => "GD7 winner-handoff signer differs from the winner",
            Self::ActiveAttemptMismatchChirho => "a different GD7 winner-handoff attempt is active",
            Self::WrongExpectedPriorChirho => "GD7 winner-handoff prior checkpoint differs",
            Self::InvalidTransitionChirho => "GD7 winner-handoff transition is invalid",
            Self::InvalidChallengeChirho => "GD7 winner-handoff challenge is invalid",
            Self::InvalidWinnerEvidenceChirho => "GD7 winner-handoff evidence is invalid",
            Self::MalformedHeadChirho => "GD7 winner-handoff head is malformed",
            Self::MalformedCheckpointChirho => "GD7 winner-handoff checkpoint is malformed",
            Self::NonCanonicalHeadChirho => "GD7 winner-handoff head is not canonical",
            Self::NonCanonicalCheckpointChirho => "GD7 winner-handoff checkpoint is not canonical",
            Self::OversizedHeadChirho => "GD7 winner-handoff head exceeds its bound",
            Self::OversizedCheckpointChirho => "GD7 winner-handoff checkpoint exceeds its bound",
            Self::InvalidHeadSignatureChirho => "GD7 winner-handoff head signature is invalid",
            Self::InvalidCheckpointSignatureChirho => {
                "GD7 winner-handoff checkpoint signature is invalid"
            }
            Self::MissingCheckpointChirho => {
                "GD7 winner-handoff head references a missing checkpoint"
            }
            Self::DigestMismatchChirho => "GD7 winner-handoff object digest differs",
            Self::ImmutableCollisionChirho => "GD7 winner-handoff immutable object collided",
            Self::PlanCheckpointChirho(_) => {
                "GD7 winner-handoff sealed-plan checkpoint verification failed"
            }
            Self::SerializationChirho => "GD7 winner-handoff serialization failed",
            Self::SigningChirho => "GD7 winner-handoff signing failed",
            Self::ForkBaselineChirho(_) => "GD7 fork-baseline evidence staging failed",
            Self::WinnerHistoryChirho(_) => "GD7 winner-history evidence staging failed",
            Self::EvidenceTransferChirho(_) => "GD7 winner evidence transfer failed",
            Self::StorageChirho => "GD7 winner-handoff storage failed",
        })
    }
}

impl Error for Gd7WinnerHandoffStoreRefusalChirho {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::PlanCheckpointChirho(error_chirho) => Some(error_chirho),
            Self::ForkBaselineChirho(error_chirho) => Some(error_chirho),
            Self::WinnerHistoryChirho(error_chirho) => Some(error_chirho),
            Self::EvidenceTransferChirho(error_chirho) => Some(error_chirho),
            _ => None,
        }
    }
}

impl From<Gd7WinnerHistoryRefusalChirho> for Gd7WinnerHandoffStoreRefusalChirho {
    fn from(error_chirho: Gd7WinnerHistoryRefusalChirho) -> Self {
        Self::WinnerHistoryChirho(error_chirho)
    }
}

impl From<Gd7ForkBaselineRefusalChirho> for Gd7WinnerHandoffStoreRefusalChirho {
    fn from(error_chirho: Gd7ForkBaselineRefusalChirho) -> Self {
        Self::ForkBaselineChirho(error_chirho)
    }
}

impl From<Gd7ReconciliationStoreRefusalChirho> for Gd7WinnerHandoffStoreRefusalChirho {
    fn from(error_chirho: Gd7ReconciliationStoreRefusalChirho) -> Self {
        Self::PlanCheckpointChirho(error_chirho)
    }
}

impl From<Gd7WinnerEvidenceTransferRefusalChirho> for Gd7WinnerHandoffStoreRefusalChirho {
    fn from(error_chirho: Gd7WinnerEvidenceTransferRefusalChirho) -> Self {
        Self::EvidenceTransferChirho(error_chirho)
    }
}

/// Winner-owned fixed-head store for exactly one current handoff per consistency group.
pub struct Gd7WinnerHandoffStoreChirho<'ports_chirho> {
    storage_chirho: &'ports_chirho dyn LedgerStoragePortChirho,
    winner_signer_chirho: &'ports_chirho dyn Gd7ReconciliationSignerPortChirho,
    consistency_group_digest_chirho: String,
    winner_node_chirho: String,
    head_path_chirho: StoragePathChirho,
}

pub fn gd7_winner_handoff_attempt_digest_chirho(
    identity_chirho: &Gd7WinnerHandoffAttemptIdentityChirho,
) -> Result<String, Gd7WinnerHandoffStoreRefusalChirho> {
    validate_attempt_identity_chirho(identity_chirho)?;
    canonical_json_chirho(identity_chirho)
        .map(|bytes_chirho| digest_bytes_chirho(&bytes_chirho))
        .map_err(|_| Gd7WinnerHandoffStoreRefusalChirho::SerializationChirho)
}

pub fn gd7_winner_handoff_head_path_chirho(
    consistency_group_digest_chirho: &str,
    winner_node_chirho: &str,
) -> Result<StoragePathChirho, Gd7WinnerHandoffStoreRefusalChirho> {
    let group_suffix_chirho =
        consistency_group_digest_suffix_chirho(consistency_group_digest_chirho)
            .ok_or(Gd7WinnerHandoffStoreRefusalChirho::InvalidIdentityChirho)?;
    if !is_lower_hex_digest_chirho(winner_node_chirho) {
        return Err(Gd7WinnerHandoffStoreRefusalChirho::InvalidIdentityChirho);
    }
    Ok(StoragePathChirho::new_chirho(format!(
        "{GD7_RECONCILIATION_NAMESPACE_CHIRHO}/groups-chirho/{}/{group_suffix_chirho}/winner-handoff-chirho/{}/{winner_node_chirho}/active-head-chirho.json",
        &group_suffix_chirho[..2],
        &winner_node_chirho[..2],
    )))
}

pub fn gd7_winner_handoff_checkpoint_path_chirho(
    checkpoint_ref_chirho: &str,
) -> Result<StoragePathChirho, Gd7WinnerHandoffStoreRefusalChirho> {
    if !is_lower_hex_digest_chirho(checkpoint_ref_chirho) {
        return Err(Gd7WinnerHandoffStoreRefusalChirho::InvalidIdentityChirho);
    }
    Ok(StoragePathChirho::new_chirho(format!(
        "{GD7_RECONCILIATION_NAMESPACE_CHIRHO}/winner-handoff-checkpoints-chirho/{}/{}/{checkpoint_ref_chirho}.json",
        &checkpoint_ref_chirho[..2],
        &checkpoint_ref_chirho[2..4],
    )))
}

impl<'ports_chirho> Gd7WinnerHandoffStoreChirho<'ports_chirho> {
    pub fn new_chirho(
        storage_chirho: &'ports_chirho dyn LedgerStoragePortChirho,
        winner_signer_chirho: &'ports_chirho dyn Gd7ReconciliationSignerPortChirho,
        consistency_group_digest_chirho: String,
        winner_node_chirho: String,
    ) -> Result<Self, Gd7WinnerHandoffStoreRefusalChirho> {
        let head_path_chirho = gd7_winner_handoff_head_path_chirho(
            &consistency_group_digest_chirho,
            &winner_node_chirho,
        )?;
        if winner_signer_chirho.key_id_chirho() != winner_node_chirho {
            return Err(Gd7WinnerHandoffStoreRefusalChirho::WrongWinnerSignerChirho);
        }
        Ok(Self {
            storage_chirho,
            winner_signer_chirho,
            consistency_group_digest_chirho,
            winner_node_chirho,
            head_path_chirho,
        })
    }

    pub fn verify_complete_held_checkpoint_chirho(
        &self,
        checkpoint_ref_chirho: &str,
        checkpoint_chirho: &Gd7HeldViewTransferCheckpointChirho,
        expected_identity_chirho: &Gd7HeldViewTransferIdentityChirho,
        expected_bundle_root_object_digest_chirho: &str,
        held_verifier_chirho: &dyn Gd7ReconciliationVerifierPortChirho,
    ) -> Result<(), Gd7HeldViewTransferStoreRefusalChirho> {
        if expected_identity_chirho.consistency_group_digest_chirho
            != self.consistency_group_digest_chirho
            || expected_identity_chirho.winner_node_chirho != self.winner_node_chirho
        {
            return Err(Gd7HeldViewTransferStoreRefusalChirho::InvalidIdentityChirho);
        }
        verify_complete_gd7_held_view_transfer_checkpoint_chirho(
            checkpoint_ref_chirho,
            checkpoint_chirho,
            expected_identity_chirho,
            expected_bundle_root_object_digest_chirho,
            held_verifier_chirho,
            self.winner_signer_chirho,
        )
    }

    /// Verify the signed held-side `PlanSealedChirho` object that authorizes this handoff and retain
    /// its exact content-addressed bytes locally before the winner enters append quiescence.
    pub fn verify_and_retain_plan_sealed_checkpoint_chirho(
        &self,
        checkpoint_ref_chirho: &str,
        checkpoint_chirho: &Gd7ReconciliationCheckpointChirho,
        expected_transfer_identity_chirho: &Gd7HeldViewTransferIdentityChirho,
        expected_winner_genesis_digest_chirho: &str,
        held_verifier_chirho: &dyn Gd7ReconciliationVerifierPortChirho,
    ) -> Result<(), Gd7ReconciliationStoreRefusalChirho> {
        let identity_chirho = &checkpoint_chirho.identity_chirho;
        if checkpoint_ref_chirho
            != expected_transfer_identity_chirho.reconciliation_checkpoint_ref_chirho
            || checkpoint_chirho.state_chirho.phase_chirho
                != Gd7ReconciliationPhaseChirho::PlanSealedChirho
            || identity_chirho.consistency_group_digest_chirho
                != expected_transfer_identity_chirho.consistency_group_digest_chirho
            || identity_chirho.consistency_group_digest_chirho
                != self.consistency_group_digest_chirho
            || identity_chirho.winner_node_chirho
                != expected_transfer_identity_chirho.winner_node_chirho
            || identity_chirho.winner_node_chirho != self.winner_node_chirho
            || identity_chirho.held_node_chirho
                != expected_transfer_identity_chirho.held_node_chirho
            || identity_chirho.winner_term_chirho
                != expected_transfer_identity_chirho.winner_term_chirho
            || identity_chirho.winner_journal_genesis_digest_chirho
                != expected_winner_genesis_digest_chirho
        {
            return Err(Gd7ReconciliationStoreRefusalChirho::WrongIdentityChirho);
        }
        verify_and_retain_gd7_reconciliation_checkpoint_chirho(
            self.storage_chirho,
            checkpoint_ref_chirho,
            checkpoint_chirho,
            held_verifier_chirho,
        )
    }

    pub fn load_current_chirho(
        &self,
    ) -> Result<Option<ActiveGd7WinnerHandoffChirho>, Gd7WinnerHandoffStoreRefusalChirho> {
        let Some(head_bytes_chirho) = read_bounded_chirho(
            self.storage_chirho,
            &self.head_path_chirho,
            MAX_GD7_WINNER_HANDOFF_HEAD_BYTES_CHIRHO,
            Gd7WinnerHandoffStoreRefusalChirho::OversizedHeadChirho,
        )?
        else {
            return Ok(None);
        };
        let head_chirho = self.parse_and_verify_head_chirho(&head_bytes_chirho)?;
        let checkpoint_path_chirho =
            gd7_winner_handoff_checkpoint_path_chirho(&head_chirho.active_checkpoint_ref_chirho)?;
        let checkpoint_bytes_chirho = read_bounded_chirho(
            self.storage_chirho,
            &checkpoint_path_chirho,
            MAX_GD7_WINNER_HANDOFF_CHECKPOINT_BYTES_CHIRHO,
            Gd7WinnerHandoffStoreRefusalChirho::OversizedCheckpointChirho,
        )?
        .ok_or(Gd7WinnerHandoffStoreRefusalChirho::MissingCheckpointChirho)?;
        if digest_bytes_chirho(&checkpoint_bytes_chirho) != head_chirho.active_checkpoint_ref_chirho
        {
            return Err(Gd7WinnerHandoffStoreRefusalChirho::DigestMismatchChirho);
        }
        let checkpoint_chirho =
            self.parse_and_verify_checkpoint_chirho(&checkpoint_bytes_chirho)?;
        let attempt_digest_chirho =
            gd7_winner_handoff_attempt_digest_chirho(&checkpoint_chirho.attempt_identity_chirho)?;
        if attempt_digest_chirho != head_chirho.attempt_digest_chirho
            || checkpoint_chirho.transition_seq_chirho != head_chirho.transition_seq_chirho
            || checkpoint_chirho.phase_chirho != head_chirho.phase_chirho
        {
            return Err(Gd7WinnerHandoffStoreRefusalChirho::InvalidTransitionChirho);
        }
        Ok(Some(ActiveGd7WinnerHandoffChirho {
            attempt_digest_chirho,
            checkpoint_ref_chirho: head_chirho.active_checkpoint_ref_chirho,
            checkpoint_chirho,
        }))
    }

    fn load_accepted_plan_handoff_chirho(
        &self,
        plan_checkpoint_ref_chirho: &str,
        plan_checkpoint_chirho: &Gd7ReconciliationCheckpointChirho,
        held_verifier_chirho: &dyn Gd7ReconciliationVerifierPortChirho,
    ) -> Result<ActiveGd7WinnerHandoffChirho, Gd7WinnerHandoffStoreRefusalChirho> {
        let active_chirho = self
            .load_current_chirho()?
            .ok_or(Gd7WinnerHandoffStoreRefusalChirho::MissingCheckpointChirho)?;
        if active_chirho.checkpoint_chirho.phase_chirho
            != Gd7WinnerHandoffPhaseChirho::AcceptedChirho
        {
            return Err(Gd7WinnerHandoffStoreRefusalChirho::InvalidTransitionChirho);
        }
        let accepted_view_chirho = &active_chirho.checkpoint_chirho.inspection_chirho;
        if plan_checkpoint_chirho
            .identity_chirho
            .winner_journal_genesis_digest_chirho
            != accepted_view_chirho
                .bundle_root_chirho
                .winner_journal_genesis_digest_chirho
            || plan_checkpoint_chirho
                .identity_chirho
                .winner_journal_tail_chirho
                != accepted_view_chirho.bundle_root_chirho.source_cut_chirho
        {
            return Err(Gd7WinnerHandoffStoreRefusalChirho::InvalidWinnerEvidenceChirho);
        }
        let transfer_identity_chirho = &active_chirho
            .checkpoint_chirho
            .attempt_identity_chirho
            .held_transfer_identity_chirho;
        self.verify_and_retain_plan_sealed_checkpoint_chirho(
            plan_checkpoint_ref_chirho,
            plan_checkpoint_chirho,
            transfer_identity_chirho,
            &plan_checkpoint_chirho
                .identity_chirho
                .winner_journal_genesis_digest_chirho,
            held_verifier_chirho,
        )?;
        Ok(active_chirho)
    }

    /// Reload the exact held-signed sealed plan named by the durable accepted barrier.
    ///
    /// # THE BARRIER IS THE AUTHORITY, NOT A GROUP HEAD
    ///
    /// This used to resolve the plan through
    /// `load_authenticated_active_gd7_reconciliation_for_group_chirho` — a fixed group-HEAD read on
    /// the winner's own storage — and then check that the head-selected ref equalled the barrier's.
    /// Its old doc said "the LOCALLY active reconciliation", and that phrase was only ever true
    /// when winner and held shared one storage. THEY DO NOT: the geo driver exists precisely to
    /// carry this evidence between two roots over HTTP, the group head is written only by the held
    /// reconciliation store on the HELD root, and the winner handoff retains the checkpoint OBJECT
    /// by ref and never a head. So on a genuine second root the head read found nothing and this
    /// function refused `MissingCheckpointChirho` before any staging could begin — which made the
    /// winner's whole adoption-evidence surface unreachable. The success ladder found it by
    /// climbing into it; history shows the shared-storage lineage (`8c95f518`), not a measured
    /// two-root protocol.
    ///
    /// The fix resolves the plan BY THE BARRIER'S OWN checkpoint ref through the content-addressed
    /// loader that is documented valid after the head advances. Two properties make that at least
    /// as strong as what it replaces, rather than merely different:
    ///
    ///   * WHAT IS LOST IS HEAD-SPECIFIC, NOT INTRINSIC. The head gave current-active selection and
    ///     head/checkpoint transition-seq equality. Neither is a statement about this checkpoint's
    ///     authority; both are statements about which checkpoint is newest, and the accepted
    ///     barrier already decided that when it accepted.
    ///   * WHAT REPLACES IT IS STRICTER BY CONSTRUCTION. The ref is taken from the durable
    ///     accepted barrier, so "the head names a different checkpoint" is no longer a condition
    ///     that can arise and be checked — it cannot arise. Every identity binding still runs, one
    ///     layer down in `load_accepted_plan_handoff_chirho` ->
    ///     `verify_and_retain_plan_sealed_checkpoint_chirho`: exact ref against the transfer
    ///     identity, `PlanSealedChirho` phase, consistency group twice, winner node twice, held
    ///     node, winner term, and the winner journal genesis digest.
    ///
    /// THERE IS NO HEAD FALLBACK, under any refusal. That is deliberate and load-bearing: a
    /// fallback would let a winner-side head — which the append funnel reads as an ACTIVE HOLD by
    /// bare presence, never parsed — become an authority input. Replicating that head was the
    /// rejected alternative; it would strand the winner's own ordinary writes.
    ///
    /// MIGRATION PATH: if this begins refusing `MissingReferencedCheckpointChirho`, the winner no
    /// longer holds the retained plan object that its own accepted barrier names — look at
    /// `verify_and_retain_plan_sealed_checkpoint_chirho` at accept time, not here.
    /// `CheckpointReferenceMismatchChirho` means the retained bytes were tampered with under an
    /// unchanged ref. `WrongIdentityChirho` from the layer below means the barrier's ref resolves
    /// to a checkpoint belonging to another group, node, or term — a foreign object, not a stale
    /// one. Each is a distinct reason on purpose; do not collapse them.
    pub fn load_accepted_plan_chirho(
        &self,
        held_verifier_chirho: &dyn Gd7ReconciliationVerifierPortChirho,
    ) -> Result<
        (
            ActiveGd7WinnerHandoffChirho,
            Gd7ReconciliationCheckpointChirho,
        ),
        Gd7WinnerHandoffStoreRefusalChirho,
    > {
        let active_chirho = self
            .load_current_chirho()?
            .ok_or(Gd7WinnerHandoffStoreRefusalChirho::MissingCheckpointChirho)?;
        if active_chirho.checkpoint_chirho.phase_chirho
            != Gd7WinnerHandoffPhaseChirho::AcceptedChirho
        {
            return Err(Gd7WinnerHandoffStoreRefusalChirho::InvalidTransitionChirho);
        }
        // Bound to the barrier BEFORE anything is read: the ref is the barrier's, and the barrier
        // was already checked to be this store's own group and winner above.
        let expected_plan_ref_chirho = active_chirho
            .checkpoint_chirho
            .attempt_identity_chirho
            .held_transfer_identity_chirho
            .reconciliation_checkpoint_ref_chirho
            .clone();
        let plan_checkpoint_chirho =
            load_authenticated_gd7_reconciliation_checkpoint_by_ref_chirho(
                self.storage_chirho,
                held_verifier_chirho,
                &expected_plan_ref_chirho,
            )?;
        self.load_accepted_plan_handoff_chirho(
            &expected_plan_ref_chirho,
            &plan_checkpoint_chirho,
            held_verifier_chirho,
        )?;
        Ok((active_chirho, plan_checkpoint_chirho))
    }

    pub fn build_accepted_evidence_manifest_chirho(
        &self,
        transfer_identity_chirho: Gd7HeldEvidenceTransferIdentityChirho,
        winner_history_root_chirho: &VerifiedGd7WinnerHistoryRootChirho,
        fork_baseline_root_chirho: &VerifiedGd7ForkBaselineRootChirho,
    ) -> Result<Gd7WinnerEvidenceManifestChirho, Gd7WinnerHandoffStoreRefusalChirho> {
        let active_chirho = self
            .load_current_chirho()?
            .ok_or(Gd7WinnerHandoffStoreRefusalChirho::MissingCheckpointChirho)?;
        let attempt_chirho = &active_chirho.checkpoint_chirho.attempt_identity_chirho;
        if active_chirho.checkpoint_chirho.phase_chirho
            != Gd7WinnerHandoffPhaseChirho::AcceptedChirho
            || transfer_identity_chirho.winner_handoff_attempt_digest_chirho
                != active_chirho.attempt_digest_chirho
            || transfer_identity_chirho.reconciliation_checkpoint_ref_chirho
                != attempt_chirho
                    .held_transfer_identity_chirho
                    .reconciliation_checkpoint_ref_chirho
            || transfer_identity_chirho.held_view_transfer_checkpoint_ref_chirho
                != attempt_chirho.held_transfer_checkpoint_ref_chirho
        {
            return Err(Gd7WinnerHandoffStoreRefusalChirho::InvalidWinnerEvidenceChirho);
        }
        build_gd7_winner_evidence_manifest_chirho(
            transfer_identity_chirho,
            winner_history_root_chirho,
            fork_baseline_root_chirho,
            self.winner_signer_chirho,
        )
        .map_err(Into::into)
    }

    pub fn fetch_accepted_evidence_page_chirho(
        &self,
        manifest_chirho: &Gd7WinnerEvidenceManifestChirho,
        requester_chirho: &str,
        grant_chirho: Gd7WinnerEvidencePageGrantChirho,
    ) -> Result<Gd7WinnerEvidencePageTransferChirho, Gd7WinnerHandoffStoreRefusalChirho> {
        let active_chirho = self
            .load_current_chirho()?
            .ok_or(Gd7WinnerHandoffStoreRefusalChirho::MissingCheckpointChirho)?;
        if active_chirho.checkpoint_chirho.phase_chirho
            != Gd7WinnerHandoffPhaseChirho::AcceptedChirho
            || manifest_chirho
                .transfer_identity_chirho
                .winner_handoff_attempt_digest_chirho
                != active_chirho.attempt_digest_chirho
        {
            return Err(Gd7WinnerHandoffStoreRefusalChirho::InvalidTransitionChirho);
        }
        fetch_gd7_winner_evidence_page_chirho(
            self.storage_chirho,
            manifest_chirho,
            requester_chirho,
            grant_chirho,
            self.winner_signer_chirho,
        )
        .map_err(Into::into)
    }

    /// Stage at most one bounded winner-history page under the exact durable accepted barrier.
    ///
    /// The held-signed `PlanSealedChirho` checkpoint is reverified and retained before every
    /// increment. The raw staging function is private to this module family, so no caller can
    /// produce a winner-history root from a Preparing, Aborted, or unrelated handoff.
    pub fn stage_next_accepted_winner_history_page_chirho(
        &self,
        plan_checkpoint_ref_chirho: &str,
        plan_checkpoint_chirho: &Gd7ReconciliationCheckpointChirho,
        held_verifier_chirho: &dyn Gd7ReconciliationVerifierPortChirho,
        winner_journal_chirho: &dyn LosingSuffixReaderChirho,
        restart_chirho: Option<&Gd7WinnerHistoryRestartChirho>,
    ) -> Result<Gd7WinnerHistoryStageOutcomeChirho, Gd7WinnerHandoffStoreRefusalChirho> {
        let active_chirho = self.load_accepted_plan_handoff_chirho(
            plan_checkpoint_ref_chirho,
            plan_checkpoint_chirho,
            held_verifier_chirho,
        )?;
        let history_identity_chirho = Gd7WinnerHistoryIdentityChirho::new_chirho(
            plan_checkpoint_chirho.identity_chirho.clone(),
            active_chirho.attempt_digest_chirho,
        )?;
        stage_next_gd7_winner_history_page_chirho(
            self.storage_chirho,
            self.winner_signer_chirho,
            winner_journal_chirho,
            &history_identity_chirho,
            restart_chirho,
        )
        .map_err(Into::into)
    }

    /// Produce one signed account-state fork baseline under the same accepted handoff barrier.
    ///
    /// Acceptance and the retained held-signed plan are checked before the O(full-history)
    /// read-only prefix replay begins. The returned root is evidence only and cannot install or
    /// adopt a journal branch.
    pub fn stage_accepted_fork_baseline_chirho(
        &self,
        plan_checkpoint_ref_chirho: &str,
        plan_checkpoint_chirho: &Gd7ReconciliationCheckpointChirho,
        held_verifier_chirho: &dyn Gd7ReconciliationVerifierPortChirho,
        winner_journal_ports_chirho: JournalPortsChirho<'_>,
        winner_journal_path_chirho: &StoragePathChirho,
        expected_cluster_chirho: &ClusterIdChirho,
    ) -> Result<VerifiedGd7ForkBaselineRootChirho, Gd7WinnerHandoffStoreRefusalChirho> {
        let active_chirho = self.load_accepted_plan_handoff_chirho(
            plan_checkpoint_ref_chirho,
            plan_checkpoint_chirho,
            held_verifier_chirho,
        )?;
        let baseline_identity_chirho = Gd7ForkBaselineIdentityChirho::new_chirho(
            plan_checkpoint_chirho.identity_chirho.clone(),
            active_chirho.attempt_digest_chirho,
        )?;
        stage_gd7_fork_baseline_chirho(
            self.storage_chirho,
            self.winner_signer_chirho,
            winner_journal_ports_chirho,
            winner_journal_path_chirho,
            expected_cluster_chirho,
            &baseline_identity_chirho,
        )
        .map_err(Into::into)
    }

    /// Commit the exact evidence sealed while the process-local preparation guard is held.
    ///
    /// Replaying the same attempt returns its existing Preparing or Accepted checkpoint.
    pub fn commit_preparing_chirho(
        &self,
        attempt_identity_chirho: Gd7WinnerHandoffAttemptIdentityChirho,
        canonical_challenge_bytes_chirho: &[u8],
        inspection_chirho: Gd7WinnerCurrentViewInspectionChirho,
        preparing_process_generation_chirho: u64,
    ) -> Result<Gd7WinnerHandoffCommitOutcomeChirho, Gd7WinnerHandoffStoreRefusalChirho> {
        let attempt_digest_chirho =
            gd7_winner_handoff_attempt_digest_chirho(&attempt_identity_chirho)?;
        let canonical_challenge_chirho = std::str::from_utf8(canonical_challenge_bytes_chirho)
            .map_err(|_| Gd7WinnerHandoffStoreRefusalChirho::InvalidChallengeChirho)?
            .to_owned();
        let active_chirho = self.load_current_chirho()?;
        if let Some(active_chirho) = &active_chirho {
            if active_chirho.attempt_digest_chirho == attempt_digest_chirho {
                return match active_chirho.checkpoint_chirho.phase_chirho {
                    Gd7WinnerHandoffPhaseChirho::PreparingChirho
                    | Gd7WinnerHandoffPhaseChirho::AcceptedChirho => {
                        self.confirm_active_chirho(active_chirho)
                    }
                    Gd7WinnerHandoffPhaseChirho::AbortedChirho => {
                        Err(Gd7WinnerHandoffStoreRefusalChirho::InvalidTransitionChirho)
                    }
                };
            }
            if active_chirho.checkpoint_chirho.phase_chirho
                != Gd7WinnerHandoffPhaseChirho::AbortedChirho
            {
                return Err(Gd7WinnerHandoffStoreRefusalChirho::ActiveAttemptMismatchChirho);
            }
        }
        let previous_checkpoint_ref_chirho = active_chirho
            .as_ref()
            .map(|active_chirho| active_chirho.checkpoint_ref_chirho.clone());
        let transition_seq_chirho = active_chirho
            .as_ref()
            .map(|active_chirho| active_chirho.checkpoint_chirho.transition_seq_chirho)
            .unwrap_or(0)
            .checked_add(u64::from(active_chirho.is_some()))
            .ok_or(Gd7WinnerHandoffStoreRefusalChirho::InvalidTransitionChirho)?;
        let checkpoint_chirho = Gd7WinnerHandoffCheckpointChirho {
            schema_chirho: GD7_WINNER_HANDOFF_CHECKPOINT_SCHEMA_V1_CHIRHO.to_owned(),
            attempt_identity_chirho,
            transition_seq_chirho,
            previous_checkpoint_ref_chirho: previous_checkpoint_ref_chirho.clone(),
            phase_chirho: Gd7WinnerHandoffPhaseChirho::PreparingChirho,
            canonical_challenge_chirho,
            inspection_chirho,
            preparing_process_generation_chirho,
            accepting_process_generation_chirho: None,
            key_id_chirho: String::new(),
            sig_chirho: String::new(),
        };
        self.commit_checkpoint_chirho(previous_checkpoint_ref_chirho.as_deref(), checkpoint_chirho)
    }

    pub fn commit_accepted_chirho(
        &self,
        attempt_digest_chirho: &str,
        expected_prior_ref_chirho: &str,
        accepting_process_generation_chirho: u64,
    ) -> Result<Gd7WinnerHandoffCommitOutcomeChirho, Gd7WinnerHandoffStoreRefusalChirho> {
        let active_chirho =
            self.load_exact_prior_chirho(attempt_digest_chirho, expected_prior_ref_chirho)?;
        if active_chirho.checkpoint_chirho.phase_chirho
            == Gd7WinnerHandoffPhaseChirho::AcceptedChirho
        {
            return self.confirm_active_chirho(&active_chirho);
        }
        if active_chirho.checkpoint_chirho.phase_chirho
            != Gd7WinnerHandoffPhaseChirho::PreparingChirho
            || accepting_process_generation_chirho == 0
        {
            return Err(Gd7WinnerHandoffStoreRefusalChirho::InvalidTransitionChirho);
        }
        let mut checkpoint_chirho = active_chirho.checkpoint_chirho;
        advance_checkpoint_chirho(&mut checkpoint_chirho, expected_prior_ref_chirho)?;
        checkpoint_chirho.phase_chirho = Gd7WinnerHandoffPhaseChirho::AcceptedChirho;
        checkpoint_chirho.accepting_process_generation_chirho =
            Some(accepting_process_generation_chirho);
        self.commit_checkpoint_chirho(Some(expected_prior_ref_chirho), checkpoint_chirho)
    }

    pub fn commit_aborted_chirho(
        &self,
        attempt_digest_chirho: &str,
        expected_prior_ref_chirho: &str,
    ) -> Result<Gd7WinnerHandoffCommitOutcomeChirho, Gd7WinnerHandoffStoreRefusalChirho> {
        let active_chirho = self
            .load_current_chirho()?
            .ok_or(Gd7WinnerHandoffStoreRefusalChirho::WrongExpectedPriorChirho)?;
        if active_chirho.attempt_digest_chirho != attempt_digest_chirho {
            return Err(Gd7WinnerHandoffStoreRefusalChirho::ActiveAttemptMismatchChirho);
        }
        if active_chirho.checkpoint_chirho.phase_chirho
            == Gd7WinnerHandoffPhaseChirho::AbortedChirho
        {
            return self.confirm_active_chirho(&active_chirho);
        }
        if active_chirho.checkpoint_ref_chirho != expected_prior_ref_chirho {
            return Err(Gd7WinnerHandoffStoreRefusalChirho::WrongExpectedPriorChirho);
        }
        if active_chirho.checkpoint_chirho.phase_chirho
            != Gd7WinnerHandoffPhaseChirho::PreparingChirho
        {
            return Err(Gd7WinnerHandoffStoreRefusalChirho::InvalidTransitionChirho);
        }
        let mut checkpoint_chirho = active_chirho.checkpoint_chirho;
        advance_checkpoint_chirho(&mut checkpoint_chirho, expected_prior_ref_chirho)?;
        checkpoint_chirho.phase_chirho = Gd7WinnerHandoffPhaseChirho::AbortedChirho;
        self.commit_checkpoint_chirho(Some(expected_prior_ref_chirho), checkpoint_chirho)
    }

    fn load_exact_prior_chirho(
        &self,
        attempt_digest_chirho: &str,
        expected_prior_ref_chirho: &str,
    ) -> Result<ActiveGd7WinnerHandoffChirho, Gd7WinnerHandoffStoreRefusalChirho> {
        if !is_lower_hex_digest_chirho(attempt_digest_chirho)
            || !is_lower_hex_digest_chirho(expected_prior_ref_chirho)
        {
            return Err(Gd7WinnerHandoffStoreRefusalChirho::InvalidIdentityChirho);
        }
        let active_chirho = self
            .load_current_chirho()?
            .ok_or(Gd7WinnerHandoffStoreRefusalChirho::WrongExpectedPriorChirho)?;
        if active_chirho.attempt_digest_chirho != attempt_digest_chirho {
            return Err(Gd7WinnerHandoffStoreRefusalChirho::ActiveAttemptMismatchChirho);
        }
        if active_chirho.checkpoint_ref_chirho != expected_prior_ref_chirho {
            return Err(Gd7WinnerHandoffStoreRefusalChirho::WrongExpectedPriorChirho);
        }
        Ok(active_chirho)
    }

    fn commit_checkpoint_chirho(
        &self,
        expected_prior_ref_chirho: Option<&str>,
        mut checkpoint_chirho: Gd7WinnerHandoffCheckpointChirho,
    ) -> Result<Gd7WinnerHandoffCommitOutcomeChirho, Gd7WinnerHandoffStoreRefusalChirho> {
        if checkpoint_chirho.previous_checkpoint_ref_chirho.as_deref() != expected_prior_ref_chirho
        {
            return Err(Gd7WinnerHandoffStoreRefusalChirho::WrongExpectedPriorChirho);
        }
        checkpoint_chirho.key_id_chirho = self.winner_signer_chirho.key_id_chirho();
        checkpoint_chirho.sig_chirho.clear();
        self.validate_checkpoint_shape_chirho(&checkpoint_chirho, false)?;
        let unsigned_bytes_chirho = canonical_json_chirho(&checkpoint_chirho)
            .map_err(|_| Gd7WinnerHandoffStoreRefusalChirho::SerializationChirho)?;
        let unsigned_line_chirho = std::str::from_utf8(&unsigned_bytes_chirho)
            .map_err(|_| Gd7WinnerHandoffStoreRefusalChirho::SerializationChirho)?;
        checkpoint_chirho.sig_chirho = self
            .winner_signer_chirho
            .sign_chirho(unsigned_line_chirho)
            .map_err(|_| Gd7WinnerHandoffStoreRefusalChirho::SigningChirho)?;
        self.validate_checkpoint_shape_chirho(&checkpoint_chirho, true)?;
        let checkpoint_bytes_chirho = canonical_json_chirho(&checkpoint_chirho)
            .map_err(|_| Gd7WinnerHandoffStoreRefusalChirho::SerializationChirho)?;
        if checkpoint_bytes_chirho.len() > MAX_GD7_WINNER_HANDOFF_CHECKPOINT_BYTES_CHIRHO {
            return Err(Gd7WinnerHandoffStoreRefusalChirho::OversizedCheckpointChirho);
        }
        let attempt_digest_chirho =
            gd7_winner_handoff_attempt_digest_chirho(&checkpoint_chirho.attempt_identity_chirho)?;
        let checkpoint_ref_chirho = digest_bytes_chirho(&checkpoint_bytes_chirho);
        let checkpoint_path_chirho =
            gd7_winner_handoff_checkpoint_path_chirho(&checkpoint_ref_chirho)?;
        create_exact_chirho(
            self.storage_chirho,
            &checkpoint_path_chirho,
            &checkpoint_bytes_chirho,
            MAX_GD7_WINNER_HANDOFF_CHECKPOINT_BYTES_CHIRHO,
        )?;

        let active_chirho = self.load_current_chirho()?;
        if active_chirho
            .as_ref()
            .map(|active_chirho| active_chirho.checkpoint_ref_chirho.as_str())
            == Some(checkpoint_ref_chirho.as_str())
        {
            return self.confirm_active_chirho(
                active_chirho
                    .as_ref()
                    .expect("the exact current checkpoint was just observed"),
            );
        }
        let actual_prior_chirho = active_chirho
            .as_ref()
            .map(|active_chirho| active_chirho.checkpoint_ref_chirho.as_str());
        if actual_prior_chirho != expected_prior_ref_chirho {
            return Err(Gd7WinnerHandoffStoreRefusalChirho::WrongExpectedPriorChirho);
        }
        validate_transition_chirho(active_chirho.as_ref(), &checkpoint_chirho)?;
        let head_bytes_chirho = self.canonical_signed_head_chirho(
            &attempt_digest_chirho,
            &checkpoint_ref_chirho,
            &checkpoint_chirho,
        )?;
        let committed_chirho = CommittedGd7WinnerHandoffChirho {
            attempt_digest_chirho,
            checkpoint_ref_chirho,
            checkpoint_chirho,
        };
        Ok(
            if self
                .storage_chirho
                .atomic_write_chirho(&self.head_path_chirho, &head_bytes_chirho)
                .is_ok()
            {
                Gd7WinnerHandoffCommitOutcomeChirho::DurableChirho(committed_chirho)
            } else {
                Gd7WinnerHandoffCommitOutcomeChirho::DurabilityUnconfirmedChirho(committed_chirho)
            },
        )
    }

    /// Reinstall the same signed fixed head and fsync its parent without creating another
    /// checkpoint or transition. Repeating this operation is safe after any ambiguous result.
    pub fn confirm_active_chirho(
        &self,
        active_chirho: &ActiveGd7WinnerHandoffChirho,
    ) -> Result<Gd7WinnerHandoffCommitOutcomeChirho, Gd7WinnerHandoffStoreRefusalChirho> {
        let checkpoint_bytes_chirho = canonical_json_chirho(&active_chirho.checkpoint_chirho)
            .map_err(|_| Gd7WinnerHandoffStoreRefusalChirho::SerializationChirho)?;
        if digest_bytes_chirho(&checkpoint_bytes_chirho) != active_chirho.checkpoint_ref_chirho {
            return Err(Gd7WinnerHandoffStoreRefusalChirho::DigestMismatchChirho);
        }
        if self.parse_and_verify_checkpoint_chirho(&checkpoint_bytes_chirho)?
            != active_chirho.checkpoint_chirho
        {
            return Err(Gd7WinnerHandoffStoreRefusalChirho::NonCanonicalCheckpointChirho);
        }
        let attempt_digest_chirho = gd7_winner_handoff_attempt_digest_chirho(
            &active_chirho.checkpoint_chirho.attempt_identity_chirho,
        )?;
        if attempt_digest_chirho != active_chirho.attempt_digest_chirho {
            return Err(Gd7WinnerHandoffStoreRefusalChirho::InvalidTransitionChirho);
        }
        let current_chirho = self.load_current_chirho()?;
        if current_chirho.as_ref() != Some(active_chirho) {
            let actual_prior_chirho = current_chirho
                .as_ref()
                .map(|current_chirho| current_chirho.checkpoint_ref_chirho.as_str());
            if actual_prior_chirho
                != active_chirho
                    .checkpoint_chirho
                    .previous_checkpoint_ref_chirho
                    .as_deref()
            {
                return Err(Gd7WinnerHandoffStoreRefusalChirho::WrongExpectedPriorChirho);
            }
            validate_transition_chirho(current_chirho.as_ref(), &active_chirho.checkpoint_chirho)?;
        }
        let head_bytes_chirho = self.canonical_signed_head_chirho(
            &active_chirho.attempt_digest_chirho,
            &active_chirho.checkpoint_ref_chirho,
            &active_chirho.checkpoint_chirho,
        )?;
        let committed_chirho = committed_from_active_chirho(active_chirho.clone());
        Ok(
            if self
                .storage_chirho
                .atomic_write_chirho(&self.head_path_chirho, &head_bytes_chirho)
                .is_ok()
            {
                Gd7WinnerHandoffCommitOutcomeChirho::DurableChirho(committed_chirho)
            } else {
                Gd7WinnerHandoffCommitOutcomeChirho::DurabilityUnconfirmedChirho(committed_chirho)
            },
        )
    }

    fn canonical_signed_head_chirho(
        &self,
        attempt_digest_chirho: &str,
        checkpoint_ref_chirho: &str,
        checkpoint_chirho: &Gd7WinnerHandoffCheckpointChirho,
    ) -> Result<Vec<u8>, Gd7WinnerHandoffStoreRefusalChirho> {
        let mut head_chirho = Gd7WinnerHandoffHeadChirho {
            schema_chirho: GD7_WINNER_HANDOFF_HEAD_SCHEMA_V1_CHIRHO.to_owned(),
            consistency_group_digest_chirho: self.consistency_group_digest_chirho.clone(),
            winner_node_chirho: self.winner_node_chirho.clone(),
            attempt_digest_chirho: attempt_digest_chirho.to_owned(),
            active_checkpoint_ref_chirho: checkpoint_ref_chirho.to_owned(),
            transition_seq_chirho: checkpoint_chirho.transition_seq_chirho,
            phase_chirho: checkpoint_chirho.phase_chirho,
            key_id_chirho: self.winner_signer_chirho.key_id_chirho(),
            sig_chirho: String::new(),
        };
        self.validate_head_shape_chirho(&head_chirho, false)?;
        let unsigned_bytes_chirho = canonical_json_chirho(&head_chirho)
            .map_err(|_| Gd7WinnerHandoffStoreRefusalChirho::SerializationChirho)?;
        let unsigned_line_chirho = std::str::from_utf8(&unsigned_bytes_chirho)
            .map_err(|_| Gd7WinnerHandoffStoreRefusalChirho::SerializationChirho)?;
        head_chirho.sig_chirho = self
            .winner_signer_chirho
            .sign_chirho(unsigned_line_chirho)
            .map_err(|_| Gd7WinnerHandoffStoreRefusalChirho::SigningChirho)?;
        self.validate_head_shape_chirho(&head_chirho, true)?;
        let bytes_chirho = canonical_json_chirho(&head_chirho)
            .map_err(|_| Gd7WinnerHandoffStoreRefusalChirho::SerializationChirho)?;
        if bytes_chirho.len() > MAX_GD7_WINNER_HANDOFF_HEAD_BYTES_CHIRHO {
            return Err(Gd7WinnerHandoffStoreRefusalChirho::OversizedHeadChirho);
        }
        Ok(bytes_chirho)
    }

    fn parse_and_verify_head_chirho(
        &self,
        bytes_chirho: &[u8],
    ) -> Result<Gd7WinnerHandoffHeadChirho, Gd7WinnerHandoffStoreRefusalChirho> {
        let head_chirho: Gd7WinnerHandoffHeadChirho = serde_json::from_slice(bytes_chirho)
            .map_err(|_| Gd7WinnerHandoffStoreRefusalChirho::MalformedHeadChirho)?;
        self.validate_head_shape_chirho(&head_chirho, true)?;
        if canonical_json_chirho(&head_chirho)
            .map_err(|_| Gd7WinnerHandoffStoreRefusalChirho::SerializationChirho)?
            .as_slice()
            != bytes_chirho
        {
            return Err(Gd7WinnerHandoffStoreRefusalChirho::NonCanonicalHeadChirho);
        }
        let mut unsigned_chirho = head_chirho.clone();
        let signature_chirho = std::mem::take(&mut unsigned_chirho.sig_chirho);
        let unsigned_bytes_chirho = canonical_json_chirho(&unsigned_chirho)
            .map_err(|_| Gd7WinnerHandoffStoreRefusalChirho::SerializationChirho)?;
        let unsigned_line_chirho = std::str::from_utf8(&unsigned_bytes_chirho)
            .map_err(|_| Gd7WinnerHandoffStoreRefusalChirho::SerializationChirho)?;
        if !self
            .winner_signer_chirho
            .verify_chirho(unsigned_line_chirho, &signature_chirho)
        {
            return Err(Gd7WinnerHandoffStoreRefusalChirho::InvalidHeadSignatureChirho);
        }
        Ok(head_chirho)
    }

    fn parse_and_verify_checkpoint_chirho(
        &self,
        bytes_chirho: &[u8],
    ) -> Result<Gd7WinnerHandoffCheckpointChirho, Gd7WinnerHandoffStoreRefusalChirho> {
        let checkpoint_chirho: Gd7WinnerHandoffCheckpointChirho =
            serde_json::from_slice(bytes_chirho)
                .map_err(|_| Gd7WinnerHandoffStoreRefusalChirho::MalformedCheckpointChirho)?;
        self.validate_checkpoint_shape_chirho(&checkpoint_chirho, true)?;
        if canonical_json_chirho(&checkpoint_chirho)
            .map_err(|_| Gd7WinnerHandoffStoreRefusalChirho::SerializationChirho)?
            .as_slice()
            != bytes_chirho
        {
            return Err(Gd7WinnerHandoffStoreRefusalChirho::NonCanonicalCheckpointChirho);
        }
        let mut unsigned_chirho = checkpoint_chirho.clone();
        let signature_chirho = std::mem::take(&mut unsigned_chirho.sig_chirho);
        let unsigned_bytes_chirho = canonical_json_chirho(&unsigned_chirho)
            .map_err(|_| Gd7WinnerHandoffStoreRefusalChirho::SerializationChirho)?;
        let unsigned_line_chirho = std::str::from_utf8(&unsigned_bytes_chirho)
            .map_err(|_| Gd7WinnerHandoffStoreRefusalChirho::SerializationChirho)?;
        if !self
            .winner_signer_chirho
            .verify_chirho(unsigned_line_chirho, &signature_chirho)
        {
            return Err(Gd7WinnerHandoffStoreRefusalChirho::InvalidCheckpointSignatureChirho);
        }
        Ok(checkpoint_chirho)
    }

    fn validate_head_shape_chirho(
        &self,
        head_chirho: &Gd7WinnerHandoffHeadChirho,
        signed_chirho: bool,
    ) -> Result<(), Gd7WinnerHandoffStoreRefusalChirho> {
        if head_chirho.schema_chirho != GD7_WINNER_HANDOFF_HEAD_SCHEMA_V1_CHIRHO
            || head_chirho.consistency_group_digest_chirho != self.consistency_group_digest_chirho
            || head_chirho.winner_node_chirho != self.winner_node_chirho
            || !is_lower_hex_digest_chirho(&head_chirho.attempt_digest_chirho)
            || !is_lower_hex_digest_chirho(&head_chirho.active_checkpoint_ref_chirho)
            || head_chirho.key_id_chirho != self.winner_node_chirho
            || if signed_chirho {
                !validate_key_and_signature_chirho(
                    &head_chirho.key_id_chirho,
                    &head_chirho.sig_chirho,
                )
            } else {
                !head_chirho.sig_chirho.is_empty()
            }
        {
            return Err(Gd7WinnerHandoffStoreRefusalChirho::InvalidIdentityChirho);
        }
        Ok(())
    }

    fn validate_checkpoint_shape_chirho(
        &self,
        checkpoint_chirho: &Gd7WinnerHandoffCheckpointChirho,
        signed_chirho: bool,
    ) -> Result<(), Gd7WinnerHandoffStoreRefusalChirho> {
        validate_attempt_identity_chirho(&checkpoint_chirho.attempt_identity_chirho)?;
        let held_transfer_identity_chirho = &checkpoint_chirho
            .attempt_identity_chirho
            .held_transfer_identity_chirho;
        if checkpoint_chirho.schema_chirho != GD7_WINNER_HANDOFF_CHECKPOINT_SCHEMA_V1_CHIRHO
            || held_transfer_identity_chirho.consistency_group_digest_chirho
                != self.consistency_group_digest_chirho
            || held_transfer_identity_chirho.winner_node_chirho != self.winner_node_chirho
            || checkpoint_chirho.preparing_process_generation_chirho == 0
            || checkpoint_chirho.key_id_chirho != self.winner_node_chirho
            || if signed_chirho {
                !validate_key_and_signature_chirho(
                    &checkpoint_chirho.key_id_chirho,
                    &checkpoint_chirho.sig_chirho,
                )
            } else {
                !checkpoint_chirho.sig_chirho.is_empty()
            }
            || match checkpoint_chirho.phase_chirho {
                Gd7WinnerHandoffPhaseChirho::PreparingChirho
                | Gd7WinnerHandoffPhaseChirho::AbortedChirho => checkpoint_chirho
                    .accepting_process_generation_chirho
                    .is_some(),
                Gd7WinnerHandoffPhaseChirho::AcceptedChirho => checkpoint_chirho
                    .accepting_process_generation_chirho
                    .is_none_or(|generation_chirho| generation_chirho == 0),
            }
        {
            return Err(Gd7WinnerHandoffStoreRefusalChirho::InvalidIdentityChirho);
        }
        let challenge_chirho = parse_canonical_gd7_winner_current_view_challenge_chirho(
            checkpoint_chirho.canonical_challenge_chirho.as_bytes(),
        )
        .map_err(|_| Gd7WinnerHandoffStoreRefusalChirho::InvalidChallengeChirho)?;
        let transfer_identity_digest_chirho = digest_bytes_chirho(
            &canonical_json_chirho(held_transfer_identity_chirho)
                .map_err(|_| Gd7WinnerHandoffStoreRefusalChirho::SerializationChirho)?,
        );
        if challenge_chirho
            .digest_chirho()
            .map_err(|_| Gd7WinnerHandoffStoreRefusalChirho::InvalidChallengeChirho)?
            != checkpoint_chirho
                .attempt_identity_chirho
                .challenge_digest_chirho
            || challenge_chirho.consistency_group_digest_chirho()
                != held_transfer_identity_chirho.consistency_group_digest_chirho
            || challenge_chirho.expected_winner_node_chirho()
                != held_transfer_identity_chirho.winner_node_chirho
            || challenge_chirho.held_node_chirho() != held_transfer_identity_chirho.held_node_chirho
            || challenge_chirho.transfer_identity_digest_chirho() != transfer_identity_digest_chirho
            || challenge_chirho.raft_term_chirho()
                != held_transfer_identity_chirho.winner_term_chirho
        {
            return Err(Gd7WinnerHandoffStoreRefusalChirho::InvalidChallengeChirho);
        }
        verify_inline_gd7_winner_current_view_inspection_chirho(
            &challenge_chirho,
            self.winner_signer_chirho,
            &checkpoint_chirho.inspection_chirho,
        )
        .map_err(|_| Gd7WinnerHandoffStoreRefusalChirho::InvalidWinnerEvidenceChirho)?;
        let evidence_chirho = &checkpoint_chirho.inspection_chirho.evidence_chirho;
        let root_chirho = &checkpoint_chirho.inspection_chirho.bundle_root_chirho;
        if evidence_chirho.winner_process_generation_chirho
            != checkpoint_chirho.preparing_process_generation_chirho
            || checkpoint_chirho
                .inspection_chirho
                .bundle_root_object_digest_chirho
                != checkpoint_chirho
                    .attempt_identity_chirho
                    .expected_bundle_root_object_digest_chirho
            || evidence_chirho.winner_journal_genesis_digest_chirho
                != root_chirho.winner_journal_genesis_digest_chirho
            || evidence_chirho.latest_verified_journal_cut_chirho != root_chirho.source_cut_chirho
        {
            return Err(Gd7WinnerHandoffStoreRefusalChirho::InvalidWinnerEvidenceChirho);
        }
        Ok(())
    }
}

fn validate_attempt_identity_chirho(
    identity_chirho: &Gd7WinnerHandoffAttemptIdentityChirho,
) -> Result<(), Gd7WinnerHandoffStoreRefusalChirho> {
    let held_transfer_identity_chirho = &identity_chirho.held_transfer_identity_chirho;
    if consistency_group_digest_suffix_chirho(
        &held_transfer_identity_chirho.consistency_group_digest_chirho,
    )
    .is_none()
        || !is_lower_hex_digest_chirho(
            &held_transfer_identity_chirho.reconciliation_checkpoint_ref_chirho,
        )
        || !is_lower_hex_digest_chirho(&held_transfer_identity_chirho.winner_node_chirho)
        || !is_lower_hex_digest_chirho(&held_transfer_identity_chirho.held_node_chirho)
        || held_transfer_identity_chirho.winner_node_chirho
            == held_transfer_identity_chirho.held_node_chirho
        || held_transfer_identity_chirho.winner_term_chirho == 0
        || !is_lower_hex_digest_chirho(&identity_chirho.held_transfer_checkpoint_ref_chirho)
        || !is_lower_hex_digest_chirho(&identity_chirho.expected_bundle_root_object_digest_chirho)
        || !is_lower_hex_digest_chirho(&identity_chirho.challenge_digest_chirho)
    {
        return Err(Gd7WinnerHandoffStoreRefusalChirho::InvalidIdentityChirho);
    }
    Ok(())
}

fn validate_transition_chirho(
    prior_chirho: Option<&ActiveGd7WinnerHandoffChirho>,
    next_chirho: &Gd7WinnerHandoffCheckpointChirho,
) -> Result<(), Gd7WinnerHandoffStoreRefusalChirho> {
    match prior_chirho {
        None => {
            if next_chirho.transition_seq_chirho != 0
                || next_chirho.previous_checkpoint_ref_chirho.is_some()
                || next_chirho.phase_chirho != Gd7WinnerHandoffPhaseChirho::PreparingChirho
            {
                return Err(Gd7WinnerHandoffStoreRefusalChirho::InvalidTransitionChirho);
            }
        }
        Some(prior_chirho) => {
            let expected_seq_chirho = prior_chirho
                .checkpoint_chirho
                .transition_seq_chirho
                .checked_add(1)
                .ok_or(Gd7WinnerHandoffStoreRefusalChirho::InvalidTransitionChirho)?;
            if next_chirho.transition_seq_chirho != expected_seq_chirho
                || next_chirho.previous_checkpoint_ref_chirho.as_deref()
                    != Some(prior_chirho.checkpoint_ref_chirho.as_str())
            {
                return Err(Gd7WinnerHandoffStoreRefusalChirho::InvalidTransitionChirho);
            }
            let same_attempt_chirho = prior_chirho.checkpoint_chirho.attempt_identity_chirho
                == next_chirho.attempt_identity_chirho;
            let valid_phase_chirho = matches!(
                (
                    prior_chirho.checkpoint_chirho.phase_chirho,
                    next_chirho.phase_chirho,
                    same_attempt_chirho,
                ),
                (
                    Gd7WinnerHandoffPhaseChirho::PreparingChirho,
                    Gd7WinnerHandoffPhaseChirho::AcceptedChirho
                        | Gd7WinnerHandoffPhaseChirho::AbortedChirho,
                    true,
                ) | (
                    Gd7WinnerHandoffPhaseChirho::AbortedChirho,
                    Gd7WinnerHandoffPhaseChirho::PreparingChirho,
                    false,
                )
            );
            if !valid_phase_chirho {
                return Err(Gd7WinnerHandoffStoreRefusalChirho::InvalidTransitionChirho);
            }
        }
    }
    Ok(())
}

fn advance_checkpoint_chirho(
    checkpoint_chirho: &mut Gd7WinnerHandoffCheckpointChirho,
    prior_ref_chirho: &str,
) -> Result<(), Gd7WinnerHandoffStoreRefusalChirho> {
    checkpoint_chirho.transition_seq_chirho = checkpoint_chirho
        .transition_seq_chirho
        .checked_add(1)
        .ok_or(Gd7WinnerHandoffStoreRefusalChirho::InvalidTransitionChirho)?;
    checkpoint_chirho.previous_checkpoint_ref_chirho = Some(prior_ref_chirho.to_owned());
    checkpoint_chirho.sig_chirho.clear();
    Ok(())
}

fn committed_from_active_chirho(
    active_chirho: ActiveGd7WinnerHandoffChirho,
) -> CommittedGd7WinnerHandoffChirho {
    CommittedGd7WinnerHandoffChirho {
        attempt_digest_chirho: active_chirho.attempt_digest_chirho,
        checkpoint_ref_chirho: active_chirho.checkpoint_ref_chirho,
        checkpoint_chirho: active_chirho.checkpoint_chirho,
    }
}

fn create_exact_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    path_chirho: &StoragePathChirho,
    bytes_chirho: &[u8],
    maximum_chirho: usize,
) -> Result<(), Gd7WinnerHandoffStoreRefusalChirho> {
    if bytes_chirho.len() > maximum_chirho {
        return Err(Gd7WinnerHandoffStoreRefusalChirho::OversizedCheckpointChirho);
    }
    match storage_chirho
        .create_durable_chirho(path_chirho, bytes_chirho)
        .map_err(|_| Gd7WinnerHandoffStoreRefusalChirho::StorageChirho)?
    {
        CreateDurableOutcomeChirho::CreatedChirho => Ok(()),
        CreateDurableOutcomeChirho::AlreadyExistsChirho => {
            let existing_chirho = read_bounded_chirho(
                storage_chirho,
                path_chirho,
                maximum_chirho,
                Gd7WinnerHandoffStoreRefusalChirho::OversizedCheckpointChirho,
            )?
            .ok_or(Gd7WinnerHandoffStoreRefusalChirho::StorageChirho)?;
            if existing_chirho == bytes_chirho {
                Ok(())
            } else {
                Err(Gd7WinnerHandoffStoreRefusalChirho::ImmutableCollisionChirho)
            }
        }
    }
}

fn read_bounded_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    path_chirho: &StoragePathChirho,
    maximum_chirho: usize,
    oversized_chirho: Gd7WinnerHandoffStoreRefusalChirho,
) -> Result<Option<Vec<u8>>, Gd7WinnerHandoffStoreRefusalChirho> {
    let Some(length_chirho) = storage_chirho
        .object_len_chirho(path_chirho)
        .map_err(|_| Gd7WinnerHandoffStoreRefusalChirho::StorageChirho)?
    else {
        return Ok(None);
    };
    if length_chirho > maximum_chirho as u64 {
        return Err(oversized_chirho);
    }
    let bytes_chirho = if length_chirho == 0 {
        Vec::new()
    } else {
        storage_chirho
            .read_exact_range_chirho(path_chirho, 0, length_chirho)
            .map_err(|_| Gd7WinnerHandoffStoreRefusalChirho::StorageChirho)?
    };
    let stable_length_chirho = storage_chirho
        .object_len_chirho(path_chirho)
        .map_err(|_| Gd7WinnerHandoffStoreRefusalChirho::StorageChirho)?;
    if bytes_chirho.len() != length_chirho as usize || stable_length_chirho != Some(length_chirho) {
        return Err(Gd7WinnerHandoffStoreRefusalChirho::StorageChirho);
    }
    Ok(Some(bytes_chirho))
}
