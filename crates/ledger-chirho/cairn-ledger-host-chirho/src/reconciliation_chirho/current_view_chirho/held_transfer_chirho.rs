// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Held-signed, restart-stable receipt of one winner current-view page chain.
//!
//! Each transition performs O(1) point reads and writes at most one immutable page, one immutable
//! checkpoint, and one fixed head. The store cannot adopt the view, move refs, append effects,
//! compensate, or re-enable ledger writes.

use super::bundle_chirho::parse_verified_inline_bundle_page_chirho;
use super::transfer_chirho::verify_gd7_winner_view_page_grant_chirho;
use super::{
    canonical_json_chirho, consistency_group_digest_suffix_chirho, digest_bytes_chirho,
    is_lower_hex_digest_chirho, parse_canonical_gd7_winner_current_view_challenge_chirho,
    validate_key_and_signature_chirho, verify_inline_gd7_winner_current_view_inspection_chirho,
    Gd7ReconciliationSignerPortChirho, Gd7ReconciliationVerifierPortChirho,
    Gd7WinnerCurrentViewInspectionChirho, Gd7WinnerViewPageGrantChirho,
    MAX_GD7_WINNER_CURRENT_VIEW_CHALLENGE_BYTES_CHIRHO,
    MAX_GD7_WINNER_VIEW_BUNDLE_PAGE_BYTES_CHIRHO,
};
use cairn_ledger_log_chirho::ports_chirho::{
    CreateDurableOutcomeChirho, LedgerStoragePortChirho, StoragePathChirho,
};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt;

const GD7_RECONCILIATION_NAMESPACE_CHIRHO: &str = "gd7-reconciliation-chirho";
pub const GD7_HELD_VIEW_TRANSFER_CHECKPOINT_SCHEMA_V1_CHIRHO: &str =
    "gd7-held-view-transfer-checkpoint-v1-chirho";
pub const GD7_HELD_VIEW_TRANSFER_HEAD_SCHEMA_V1_CHIRHO: &str =
    "gd7-held-view-transfer-head-v1-chirho";
pub const MAX_GD7_HELD_VIEW_TRANSFER_CHECKPOINT_BYTES_CHIRHO: usize = 64 * 1024;
pub const MAX_GD7_HELD_VIEW_TRANSFER_HEAD_BYTES_CHIRHO: usize = 8 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gd7HeldViewTransferIdentityChirho {
    pub consistency_group_digest_chirho: String,
    pub reconciliation_checkpoint_ref_chirho: String,
    pub winner_node_chirho: String,
    pub held_node_chirho: String,
    pub winner_term_chirho: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants must carry the Chirho suffix"
)]
pub enum Gd7HeldViewTransferPhaseChirho {
    StagingChirho,
    ChallengeIssuedChirho,
    ReceivingChirho,
    CompleteChirho,
    StaleChirho,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants must carry the Chirho suffix"
)]
pub enum Gd7HeldViewTransferStaleReasonChirho {
    AuthorityDriftChirho,
    WinnerRefusedChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gd7HeldViewTransferCheckpointChirho {
    pub schema_chirho: String,
    pub identity_chirho: Gd7HeldViewTransferIdentityChirho,
    pub transition_seq_chirho: u64,
    pub previous_checkpoint_ref_chirho: Option<String>,
    pub phase_chirho: Gd7HeldViewTransferPhaseChirho,
    pub expected_stage_index_chirho: u64,
    /// Canonical retry evidence only. This never reconstructs the opaque issued challenge needed
    /// by a later adoption verifier; adoption must mint and consume a fresh local challenge.
    pub canonical_challenge_chirho: Option<String>,
    pub staged_bundle_root_ref_chirho: Option<String>,
    pub staged_page_count_chirho: Option<u64>,
    pub staged_row_count_chirho: Option<u64>,
    pub inspection_chirho: Option<Gd7WinnerCurrentViewInspectionChirho>,
    pub next_page_grant_chirho: Option<Gd7WinnerViewPageGrantChirho>,
    pub received_page_count_chirho: u64,
    pub received_row_count_chirho: u64,
    pub latest_received_page_ref_chirho: Option<String>,
    pub stale_reason_chirho: Option<Gd7HeldViewTransferStaleReasonChirho>,
    pub key_id_chirho: String,
    pub sig_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gd7HeldViewTransferHeadChirho {
    pub schema_chirho: String,
    pub consistency_group_digest_chirho: String,
    pub reconciliation_checkpoint_ref_chirho: String,
    pub transfer_identity_digest_chirho: String,
    pub active_checkpoint_ref_chirho: String,
    pub transition_seq_chirho: u64,
    pub phase_chirho: Gd7HeldViewTransferPhaseChirho,
    pub key_id_chirho: String,
    pub sig_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActiveGd7HeldViewTransferChirho {
    pub checkpoint_ref_chirho: String,
    pub checkpoint_chirho: Gd7HeldViewTransferCheckpointChirho,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommittedGd7HeldViewTransferChirho {
    pub checkpoint_ref_chirho: String,
    pub checkpoint_chirho: Gd7HeldViewTransferCheckpointChirho,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants must carry the Chirho suffix"
)]
pub enum Gd7HeldViewTransferStoreRefusalChirho {
    InvalidIdentityChirho,
    WrongHeldSignerChirho,
    WrongWinnerVerifierChirho,
    InvalidStateChirho,
    WrongExpectedPriorChirho,
    InvalidTransitionChirho,
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
    InvalidWinnerEvidenceChirho,
    InvalidGrantChirho,
    InvalidPageChirho,
    ImmutableCollisionChirho,
    SerializationChirho,
    SigningChirho,
    StorageChirho,
}

impl fmt::Display for Gd7HeldViewTransferStoreRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter_chirho.write_str(match self {
            Self::InvalidIdentityChirho => "GD7 held view-transfer identity is invalid",
            Self::WrongHeldSignerChirho => "GD7 held transfer signer differs from the held node",
            Self::WrongWinnerVerifierChirho => {
                "GD7 held transfer verifier differs from the winner node"
            }
            Self::InvalidStateChirho => "GD7 held view-transfer state is invalid",
            Self::WrongExpectedPriorChirho => "GD7 held transfer prior checkpoint differs",
            Self::InvalidTransitionChirho => "GD7 held view-transfer transition is invalid",
            Self::MalformedHeadChirho => "GD7 held view-transfer head is malformed",
            Self::MalformedCheckpointChirho => "GD7 held view-transfer checkpoint is malformed",
            Self::NonCanonicalHeadChirho => "GD7 held view-transfer head is not canonical",
            Self::NonCanonicalCheckpointChirho => {
                "GD7 held view-transfer checkpoint is not canonical"
            }
            Self::OversizedHeadChirho => "GD7 held view-transfer head exceeds its bound",
            Self::OversizedCheckpointChirho => {
                "GD7 held view-transfer checkpoint exceeds its bound"
            }
            Self::InvalidHeadSignatureChirho => "GD7 held view-transfer head signature is invalid",
            Self::InvalidCheckpointSignatureChirho => {
                "GD7 held view-transfer checkpoint signature is invalid"
            }
            Self::MissingCheckpointChirho => {
                "GD7 held view-transfer head references a missing checkpoint"
            }
            Self::DigestMismatchChirho => "GD7 held view-transfer object digest differs",
            Self::InvalidWinnerEvidenceChirho => "GD7 winner view evidence is invalid",
            Self::InvalidGrantChirho => "GD7 winner page grant is invalid",
            Self::InvalidPageChirho => "GD7 received winner page is invalid",
            Self::ImmutableCollisionChirho => "GD7 held transfer immutable object collided",
            Self::SerializationChirho => "GD7 held view-transfer serialization failed",
            Self::SigningChirho => "GD7 held view-transfer signing failed",
            Self::StorageChirho => "GD7 held view-transfer storage failed",
        })
    }
}

impl Error for Gd7HeldViewTransferStoreRefusalChirho {}

pub struct Gd7HeldViewTransferStoreChirho<'ports_chirho> {
    storage_chirho: &'ports_chirho dyn LedgerStoragePortChirho,
    held_signer_chirho: &'ports_chirho dyn Gd7ReconciliationSignerPortChirho,
    winner_verifier_chirho: &'ports_chirho dyn Gd7ReconciliationVerifierPortChirho,
    identity_chirho: Gd7HeldViewTransferIdentityChirho,
    identity_digest_chirho: String,
    head_path_chirho: StoragePathChirho,
}

pub fn gd7_held_view_transfer_head_path_chirho(
    identity_chirho: &Gd7HeldViewTransferIdentityChirho,
) -> Result<StoragePathChirho, Gd7HeldViewTransferStoreRefusalChirho> {
    validate_identity_chirho(identity_chirho)?;
    let group_suffix_chirho =
        consistency_group_digest_suffix_chirho(&identity_chirho.consistency_group_digest_chirho)
            .ok_or(Gd7HeldViewTransferStoreRefusalChirho::InvalidIdentityChirho)?;
    let reconciliation_ref_chirho = &identity_chirho.reconciliation_checkpoint_ref_chirho;
    Ok(StoragePathChirho::new_chirho(format!(
        "{GD7_RECONCILIATION_NAMESPACE_CHIRHO}/groups-chirho/{}/{}/{group_suffix_chirho}/held-view-transfer-chirho/{}/{}/{reconciliation_ref_chirho}/active-head-chirho.json",
        &group_suffix_chirho[..2],
        &group_suffix_chirho[2..4],
        &reconciliation_ref_chirho[..2],
        &reconciliation_ref_chirho[2..4],
    )))
}

pub fn gd7_held_view_transfer_checkpoint_path_chirho(
    checkpoint_ref_chirho: &str,
) -> Result<StoragePathChirho, Gd7HeldViewTransferStoreRefusalChirho> {
    digest_sharded_path_chirho(
        "held-view-transfer-checkpoints-chirho",
        checkpoint_ref_chirho,
    )
}

pub fn gd7_held_view_transfer_received_page_path_chirho(
    page_ref_chirho: &str,
) -> Result<StoragePathChirho, Gd7HeldViewTransferStoreRefusalChirho> {
    digest_sharded_path_chirho("held-view-transfer-pages-chirho", page_ref_chirho)
}

/// Verify the exact held-signed `CompleteChirho` checkpoint presented to a winner handoff.
///
/// This is an O(1) authority check over the checkpoint and its inline winner evidence. It does not
/// replace the held-side O(pages + rows) received-chain verification required immediately before
/// adoption.
pub fn verify_complete_gd7_held_view_transfer_checkpoint_chirho(
    checkpoint_ref_chirho: &str,
    checkpoint_chirho: &Gd7HeldViewTransferCheckpointChirho,
    expected_identity_chirho: &Gd7HeldViewTransferIdentityChirho,
    expected_bundle_root_object_digest_chirho: &str,
    held_verifier_chirho: &dyn Gd7ReconciliationVerifierPortChirho,
    winner_verifier_chirho: &dyn Gd7ReconciliationVerifierPortChirho,
) -> Result<(), Gd7HeldViewTransferStoreRefusalChirho> {
    validate_identity_chirho(expected_identity_chirho)?;
    if held_verifier_chirho.key_id_chirho() != expected_identity_chirho.held_node_chirho {
        return Err(Gd7HeldViewTransferStoreRefusalChirho::WrongHeldSignerChirho);
    }
    if winner_verifier_chirho.key_id_chirho() != expected_identity_chirho.winner_node_chirho {
        return Err(Gd7HeldViewTransferStoreRefusalChirho::WrongWinnerVerifierChirho);
    }
    validate_signed_checkpoint_chirho(checkpoint_chirho)?;
    if checkpoint_chirho.identity_chirho != *expected_identity_chirho
        || checkpoint_chirho.phase_chirho != Gd7HeldViewTransferPhaseChirho::CompleteChirho
        || !is_lower_hex_digest_chirho(checkpoint_ref_chirho)
        || !is_lower_hex_digest_chirho(expected_bundle_root_object_digest_chirho)
    {
        return Err(Gd7HeldViewTransferStoreRefusalChirho::InvalidStateChirho);
    }
    let checkpoint_bytes_chirho = canonical_json_chirho(checkpoint_chirho)
        .map_err(|_| Gd7HeldViewTransferStoreRefusalChirho::SerializationChirho)?;
    if checkpoint_bytes_chirho.len() > MAX_GD7_HELD_VIEW_TRANSFER_CHECKPOINT_BYTES_CHIRHO {
        return Err(Gd7HeldViewTransferStoreRefusalChirho::OversizedCheckpointChirho);
    }
    if digest_bytes_chirho(&checkpoint_bytes_chirho) != checkpoint_ref_chirho {
        return Err(Gd7HeldViewTransferStoreRefusalChirho::DigestMismatchChirho);
    }
    let mut unsigned_checkpoint_chirho = checkpoint_chirho.clone();
    let checkpoint_signature_chirho = std::mem::take(&mut unsigned_checkpoint_chirho.sig_chirho);
    let unsigned_checkpoint_bytes_chirho = canonical_json_chirho(&unsigned_checkpoint_chirho)
        .map_err(|_| Gd7HeldViewTransferStoreRefusalChirho::SerializationChirho)?;
    let unsigned_checkpoint_line_chirho = std::str::from_utf8(&unsigned_checkpoint_bytes_chirho)
        .map_err(|_| Gd7HeldViewTransferStoreRefusalChirho::SerializationChirho)?;
    if !held_verifier_chirho.verify_chirho(
        unsigned_checkpoint_line_chirho,
        &checkpoint_signature_chirho,
    ) {
        return Err(Gd7HeldViewTransferStoreRefusalChirho::InvalidCheckpointSignatureChirho);
    }

    let canonical_challenge_chirho = checkpoint_chirho
        .canonical_challenge_chirho
        .as_deref()
        .ok_or(Gd7HeldViewTransferStoreRefusalChirho::InvalidStateChirho)?;
    let challenge_chirho = parse_canonical_gd7_winner_current_view_challenge_chirho(
        canonical_challenge_chirho.as_bytes(),
    )
    .map_err(|_| Gd7HeldViewTransferStoreRefusalChirho::InvalidStateChirho)?;
    let identity_digest_chirho = digest_bytes_chirho(
        &canonical_json_chirho(expected_identity_chirho)
            .map_err(|_| Gd7HeldViewTransferStoreRefusalChirho::SerializationChirho)?,
    );
    if challenge_chirho.consistency_group_digest_chirho()
        != expected_identity_chirho.consistency_group_digest_chirho
        || challenge_chirho.expected_winner_node_chirho()
            != expected_identity_chirho.winner_node_chirho
        || challenge_chirho.held_node_chirho() != expected_identity_chirho.held_node_chirho
        || challenge_chirho.transfer_identity_digest_chirho() != identity_digest_chirho
        || challenge_chirho.raft_term_chirho() != expected_identity_chirho.winner_term_chirho
    {
        return Err(Gd7HeldViewTransferStoreRefusalChirho::InvalidStateChirho);
    }
    let inspection_chirho = checkpoint_chirho
        .inspection_chirho
        .as_ref()
        .ok_or(Gd7HeldViewTransferStoreRefusalChirho::InvalidStateChirho)?;
    verify_inline_gd7_winner_current_view_inspection_chirho(
        &challenge_chirho,
        winner_verifier_chirho,
        inspection_chirho,
    )
    .map_err(|_| Gd7HeldViewTransferStoreRefusalChirho::InvalidWinnerEvidenceChirho)?;
    let root_chirho = &inspection_chirho.bundle_root_chirho;
    if checkpoint_chirho.staged_bundle_root_ref_chirho.as_deref()
        != Some(expected_bundle_root_object_digest_chirho)
        || inspection_chirho.bundle_root_object_digest_chirho
            != expected_bundle_root_object_digest_chirho
        || checkpoint_chirho.staged_page_count_chirho != Some(root_chirho.page_count_chirho)
        || checkpoint_chirho.staged_row_count_chirho != Some(root_chirho.row_count_chirho)
        || checkpoint_chirho.received_page_count_chirho != root_chirho.page_count_chirho
        || checkpoint_chirho.received_row_count_chirho != root_chirho.row_count_chirho
        || checkpoint_chirho.next_page_grant_chirho.is_some()
        || (root_chirho.page_count_chirho == 0)
            != checkpoint_chirho.latest_received_page_ref_chirho.is_none()
    {
        return Err(Gd7HeldViewTransferStoreRefusalChirho::InvalidWinnerEvidenceChirho);
    }
    Ok(())
}

impl<'ports_chirho> Gd7HeldViewTransferStoreChirho<'ports_chirho> {
    pub fn new_chirho(
        storage_chirho: &'ports_chirho dyn LedgerStoragePortChirho,
        held_signer_chirho: &'ports_chirho dyn Gd7ReconciliationSignerPortChirho,
        winner_verifier_chirho: &'ports_chirho dyn Gd7ReconciliationVerifierPortChirho,
        identity_chirho: Gd7HeldViewTransferIdentityChirho,
    ) -> Result<Self, Gd7HeldViewTransferStoreRefusalChirho> {
        validate_identity_chirho(&identity_chirho)?;
        if held_signer_chirho.key_id_chirho() != identity_chirho.held_node_chirho {
            return Err(Gd7HeldViewTransferStoreRefusalChirho::WrongHeldSignerChirho);
        }
        if winner_verifier_chirho.key_id_chirho() != identity_chirho.winner_node_chirho {
            return Err(Gd7HeldViewTransferStoreRefusalChirho::WrongWinnerVerifierChirho);
        }
        let identity_digest_chirho = digest_bytes_chirho(
            &canonical_json_chirho(&identity_chirho)
                .map_err(|_| Gd7HeldViewTransferStoreRefusalChirho::SerializationChirho)?,
        );
        let head_path_chirho = gd7_held_view_transfer_head_path_chirho(&identity_chirho)?;
        Ok(Self {
            storage_chirho,
            held_signer_chirho,
            winner_verifier_chirho,
            identity_chirho,
            identity_digest_chirho,
            head_path_chirho,
        })
    }

    pub fn identity_digest_chirho(&self) -> &str {
        &self.identity_digest_chirho
    }

    pub fn identity_chirho(&self) -> &Gd7HeldViewTransferIdentityChirho {
        &self.identity_chirho
    }

    pub fn ensure_initialized_chirho(
        &self,
    ) -> Result<ActiveGd7HeldViewTransferChirho, Gd7HeldViewTransferStoreRefusalChirho> {
        if let Some(active_chirho) = self.load_active_chirho()? {
            return Ok(active_chirho);
        }
        let checkpoint_chirho = Gd7HeldViewTransferCheckpointChirho {
            schema_chirho: GD7_HELD_VIEW_TRANSFER_CHECKPOINT_SCHEMA_V1_CHIRHO.to_owned(),
            identity_chirho: self.identity_chirho.clone(),
            transition_seq_chirho: 0,
            previous_checkpoint_ref_chirho: None,
            phase_chirho: Gd7HeldViewTransferPhaseChirho::StagingChirho,
            expected_stage_index_chirho: 0,
            canonical_challenge_chirho: None,
            staged_bundle_root_ref_chirho: None,
            staged_page_count_chirho: None,
            staged_row_count_chirho: None,
            inspection_chirho: None,
            next_page_grant_chirho: None,
            received_page_count_chirho: 0,
            received_row_count_chirho: 0,
            latest_received_page_ref_chirho: None,
            stale_reason_chirho: None,
            key_id_chirho: String::new(),
            sig_chirho: String::new(),
        };
        self.commit_checkpoint_chirho(None, checkpoint_chirho)
            .map(active_from_committed_chirho)
    }

    pub fn load_active_chirho(
        &self,
    ) -> Result<Option<ActiveGd7HeldViewTransferChirho>, Gd7HeldViewTransferStoreRefusalChirho>
    {
        let Some(head_bytes_chirho) = read_bounded_chirho(
            self.storage_chirho,
            &self.head_path_chirho,
            MAX_GD7_HELD_VIEW_TRANSFER_HEAD_BYTES_CHIRHO,
            Gd7HeldViewTransferStoreRefusalChirho::OversizedHeadChirho,
        )?
        else {
            return Ok(None);
        };
        let head_chirho = self.parse_and_verify_head_chirho(&head_bytes_chirho)?;
        let checkpoint_path_chirho = gd7_held_view_transfer_checkpoint_path_chirho(
            &head_chirho.active_checkpoint_ref_chirho,
        )?;
        let checkpoint_bytes_chirho = read_bounded_chirho(
            self.storage_chirho,
            &checkpoint_path_chirho,
            MAX_GD7_HELD_VIEW_TRANSFER_CHECKPOINT_BYTES_CHIRHO,
            Gd7HeldViewTransferStoreRefusalChirho::OversizedCheckpointChirho,
        )?
        .ok_or(Gd7HeldViewTransferStoreRefusalChirho::MissingCheckpointChirho)?;
        if digest_bytes_chirho(&checkpoint_bytes_chirho) != head_chirho.active_checkpoint_ref_chirho
        {
            return Err(Gd7HeldViewTransferStoreRefusalChirho::DigestMismatchChirho);
        }
        let checkpoint_chirho =
            self.parse_and_verify_checkpoint_chirho(&checkpoint_bytes_chirho)?;
        if checkpoint_chirho.transition_seq_chirho != head_chirho.transition_seq_chirho
            || checkpoint_chirho.phase_chirho != head_chirho.phase_chirho
        {
            return Err(Gd7HeldViewTransferStoreRefusalChirho::InvalidStateChirho);
        }
        Ok(Some(ActiveGd7HeldViewTransferChirho {
            checkpoint_ref_chirho: head_chirho.active_checkpoint_ref_chirho,
            checkpoint_chirho,
        }))
    }

    pub fn commit_stage_advanced_chirho(
        &self,
        expected_prior_ref_chirho: &str,
        expected_stage_index_chirho: u64,
    ) -> Result<CommittedGd7HeldViewTransferChirho, Gd7HeldViewTransferStoreRefusalChirho> {
        let active_chirho = self.load_exact_prior_chirho(expected_prior_ref_chirho)?;
        let prior_chirho = &active_chirho.checkpoint_chirho;
        if prior_chirho.phase_chirho != Gd7HeldViewTransferPhaseChirho::StagingChirho
            || prior_chirho.expected_stage_index_chirho != expected_stage_index_chirho
        {
            return Err(Gd7HeldViewTransferStoreRefusalChirho::InvalidTransitionChirho);
        }
        let mut next_chirho = prior_chirho.clone();
        advance_checkpoint_coordinate_chirho(&mut next_chirho, expected_prior_ref_chirho)?;
        next_chirho.expected_stage_index_chirho = expected_stage_index_chirho
            .checked_add(1)
            .ok_or(Gd7HeldViewTransferStoreRefusalChirho::InvalidTransitionChirho)?;
        self.commit_checkpoint_chirho(Some(expected_prior_ref_chirho), next_chirho)
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the transition binds one exact staged root and its persisted challenge"
    )]
    pub fn commit_challenge_issued_chirho(
        &self,
        expected_prior_ref_chirho: &str,
        expected_stage_index_chirho: u64,
        staged_bundle_root_ref_chirho: String,
        staged_page_count_chirho: u64,
        staged_row_count_chirho: u64,
        canonical_challenge_bytes_chirho: &[u8],
    ) -> Result<CommittedGd7HeldViewTransferChirho, Gd7HeldViewTransferStoreRefusalChirho> {
        let active_chirho = self.load_exact_prior_chirho(expected_prior_ref_chirho)?;
        let prior_chirho = &active_chirho.checkpoint_chirho;
        let challenge_chirho = parse_canonical_gd7_winner_current_view_challenge_chirho(
            canonical_challenge_bytes_chirho,
        )
        .map_err(|_| Gd7HeldViewTransferStoreRefusalChirho::InvalidStateChirho)?;
        if prior_chirho.phase_chirho != Gd7HeldViewTransferPhaseChirho::StagingChirho
            || prior_chirho.expected_stage_index_chirho != expected_stage_index_chirho
            || !is_lower_hex_digest_chirho(&staged_bundle_root_ref_chirho)
            || challenge_chirho.consistency_group_digest_chirho()
                != self.identity_chirho.consistency_group_digest_chirho
            || challenge_chirho.expected_winner_node_chirho()
                != self.identity_chirho.winner_node_chirho
            || challenge_chirho.held_node_chirho() != self.identity_chirho.held_node_chirho
            || challenge_chirho.transfer_identity_digest_chirho() != self.identity_digest_chirho
            || challenge_chirho.raft_term_chirho() != self.identity_chirho.winner_term_chirho
            || (staged_page_count_chirho == 0) != (staged_row_count_chirho == 0)
        {
            return Err(Gd7HeldViewTransferStoreRefusalChirho::InvalidTransitionChirho);
        }
        let canonical_challenge_chirho = std::str::from_utf8(canonical_challenge_bytes_chirho)
            .map_err(|_| Gd7HeldViewTransferStoreRefusalChirho::InvalidStateChirho)?
            .to_owned();
        let mut next_chirho = prior_chirho.clone();
        advance_checkpoint_coordinate_chirho(&mut next_chirho, expected_prior_ref_chirho)?;
        next_chirho.phase_chirho = Gd7HeldViewTransferPhaseChirho::ChallengeIssuedChirho;
        next_chirho.expected_stage_index_chirho = expected_stage_index_chirho
            .checked_add(1)
            .ok_or(Gd7HeldViewTransferStoreRefusalChirho::InvalidTransitionChirho)?;
        next_chirho.canonical_challenge_chirho = Some(canonical_challenge_chirho);
        next_chirho.staged_bundle_root_ref_chirho = Some(staged_bundle_root_ref_chirho);
        next_chirho.staged_page_count_chirho = Some(staged_page_count_chirho);
        next_chirho.staged_row_count_chirho = Some(staged_row_count_chirho);
        self.commit_checkpoint_chirho(Some(expected_prior_ref_chirho), next_chirho)
    }

    pub fn commit_sealed_chirho(
        &self,
        expected_prior_ref_chirho: &str,
        inspection_chirho: Gd7WinnerCurrentViewInspectionChirho,
        first_page_grant_chirho: Option<Gd7WinnerViewPageGrantChirho>,
    ) -> Result<CommittedGd7HeldViewTransferChirho, Gd7HeldViewTransferStoreRefusalChirho> {
        let active_chirho = self.load_exact_prior_chirho(expected_prior_ref_chirho)?;
        let prior_chirho = &active_chirho.checkpoint_chirho;
        if prior_chirho.phase_chirho != Gd7HeldViewTransferPhaseChirho::ChallengeIssuedChirho {
            return Err(Gd7HeldViewTransferStoreRefusalChirho::InvalidTransitionChirho);
        }
        let challenge_chirho = parse_canonical_gd7_winner_current_view_challenge_chirho(
            prior_chirho
                .canonical_challenge_chirho
                .as_deref()
                .ok_or(Gd7HeldViewTransferStoreRefusalChirho::InvalidStateChirho)?
                .as_bytes(),
        )
        .map_err(|_| Gd7HeldViewTransferStoreRefusalChirho::InvalidStateChirho)?;
        verify_inline_gd7_winner_current_view_inspection_chirho(
            &challenge_chirho,
            self.winner_verifier_chirho,
            &inspection_chirho,
        )
        .map_err(|_| Gd7HeldViewTransferStoreRefusalChirho::InvalidWinnerEvidenceChirho)?;
        let root_chirho = &inspection_chirho.bundle_root_chirho;
        if prior_chirho.staged_bundle_root_ref_chirho.as_deref()
            != Some(inspection_chirho.bundle_root_object_digest_chirho.as_str())
            || prior_chirho.staged_page_count_chirho != Some(root_chirho.page_count_chirho)
            || prior_chirho.staged_row_count_chirho != Some(root_chirho.row_count_chirho)
        {
            return Err(Gd7HeldViewTransferStoreRefusalChirho::InvalidWinnerEvidenceChirho);
        }
        match (
            &first_page_grant_chirho,
            root_chirho.lowest_page_ref_chirho.as_deref(),
        ) {
            (None, None) if root_chirho.page_count_chirho == 0 => {}
            (Some(grant_chirho), Some(lowest_page_ref_chirho)) => {
                self.verify_grant_for_inspection_chirho(grant_chirho, &inspection_chirho)?;
                if grant_chirho.page_index_chirho
                    != root_chirho
                        .page_count_chirho
                        .checked_sub(1)
                        .ok_or(Gd7HeldViewTransferStoreRefusalChirho::InvalidGrantChirho)?
                    || grant_chirho.page_object_digest_chirho != lowest_page_ref_chirho
                {
                    return Err(Gd7HeldViewTransferStoreRefusalChirho::InvalidGrantChirho);
                }
            }
            _ => return Err(Gd7HeldViewTransferStoreRefusalChirho::InvalidGrantChirho),
        }
        let mut next_chirho = prior_chirho.clone();
        advance_checkpoint_coordinate_chirho(&mut next_chirho, expected_prior_ref_chirho)?;
        next_chirho.phase_chirho = if first_page_grant_chirho.is_some() {
            Gd7HeldViewTransferPhaseChirho::ReceivingChirho
        } else {
            Gd7HeldViewTransferPhaseChirho::CompleteChirho
        };
        next_chirho.inspection_chirho = Some(inspection_chirho);
        next_chirho.next_page_grant_chirho = first_page_grant_chirho;
        self.commit_checkpoint_chirho(Some(expected_prior_ref_chirho), next_chirho)
    }

    pub fn commit_received_page_chirho(
        &self,
        expected_prior_ref_chirho: &str,
        grant_chirho: Gd7WinnerViewPageGrantChirho,
        canonical_page_bytes_chirho: &[u8],
        next_grant_chirho: Option<Gd7WinnerViewPageGrantChirho>,
    ) -> Result<CommittedGd7HeldViewTransferChirho, Gd7HeldViewTransferStoreRefusalChirho> {
        let active_chirho = self.load_exact_prior_chirho(expected_prior_ref_chirho)?;
        let prior_chirho = &active_chirho.checkpoint_chirho;
        if prior_chirho.phase_chirho != Gd7HeldViewTransferPhaseChirho::ReceivingChirho
            || prior_chirho.next_page_grant_chirho.as_ref() != Some(&grant_chirho)
        {
            return Err(Gd7HeldViewTransferStoreRefusalChirho::InvalidTransitionChirho);
        }
        let inspection_chirho = prior_chirho
            .inspection_chirho
            .as_ref()
            .ok_or(Gd7HeldViewTransferStoreRefusalChirho::InvalidStateChirho)?;
        self.verify_grant_for_inspection_chirho(&grant_chirho, inspection_chirho)?;
        let verified_page_chirho =
            parse_verified_inline_bundle_page_chirho(canonical_page_bytes_chirho)
                .map_err(|_| Gd7HeldViewTransferStoreRefusalChirho::InvalidPageChirho)?;
        let page_chirho = &verified_page_chirho.page_chirho;
        let root_chirho = &inspection_chirho.bundle_root_chirho;
        let expected_page_index_chirho = root_chirho
            .page_count_chirho
            .checked_sub(prior_chirho.received_page_count_chirho)
            .and_then(|remaining_chirho| remaining_chirho.checked_sub(1))
            .ok_or(Gd7HeldViewTransferStoreRefusalChirho::InvalidPageChirho)?;
        if verified_page_chirho.object_digest_chirho != grant_chirho.page_object_digest_chirho
            || grant_chirho.page_index_chirho != expected_page_index_chirho
            || page_chirho.page_index_chirho != grant_chirho.page_index_chirho
            || page_chirho.consistency_group_digest_chirho
                != root_chirho.consistency_group_digest_chirho
            || page_chirho.projection_fold_ref_chirho != root_chirho.projection_fold_ref_chirho
            || page_chirho.winner_journal_genesis_digest_chirho
                != root_chirho.winner_journal_genesis_digest_chirho
            || page_chirho.source_cut_chirho != root_chirho.source_cut_chirho
        {
            return Err(Gd7HeldViewTransferStoreRefusalChirho::InvalidPageChirho);
        }
        match (
            &next_grant_chirho,
            page_chirho.higher_page_ref_chirho.as_deref(),
        ) {
            (Some(next_grant_chirho), Some(higher_page_ref_chirho)) => {
                self.verify_grant_for_inspection_chirho(next_grant_chirho, inspection_chirho)?;
                if grant_chirho.page_index_chirho.checked_sub(1)
                    != Some(next_grant_chirho.page_index_chirho)
                    || next_grant_chirho.page_object_digest_chirho != higher_page_ref_chirho
                {
                    return Err(Gd7HeldViewTransferStoreRefusalChirho::InvalidGrantChirho);
                }
            }
            (None, None) if grant_chirho.page_index_chirho == 0 => {}
            _ => return Err(Gd7HeldViewTransferStoreRefusalChirho::InvalidGrantChirho),
        }
        let received_page_count_chirho = prior_chirho
            .received_page_count_chirho
            .checked_add(1)
            .ok_or(Gd7HeldViewTransferStoreRefusalChirho::InvalidPageChirho)?;
        let local_row_count_chirho = u64::try_from(page_chirho.rows_chirho.len())
            .map_err(|_| Gd7HeldViewTransferStoreRefusalChirho::InvalidPageChirho)?;
        let received_row_count_chirho = prior_chirho
            .received_row_count_chirho
            .checked_add(local_row_count_chirho)
            .ok_or(Gd7HeldViewTransferStoreRefusalChirho::InvalidPageChirho)?;
        if next_grant_chirho.is_none()
            && (received_page_count_chirho != root_chirho.page_count_chirho
                || received_row_count_chirho != root_chirho.row_count_chirho)
        {
            return Err(Gd7HeldViewTransferStoreRefusalChirho::InvalidPageChirho);
        }

        let received_page_path_chirho = gd7_held_view_transfer_received_page_path_chirho(
            &verified_page_chirho.object_digest_chirho,
        )?;
        create_exact_chirho(
            self.storage_chirho,
            &received_page_path_chirho,
            canonical_page_bytes_chirho,
            MAX_GD7_WINNER_VIEW_BUNDLE_PAGE_BYTES_CHIRHO,
        )?;

        let mut next_chirho = prior_chirho.clone();
        advance_checkpoint_coordinate_chirho(&mut next_chirho, expected_prior_ref_chirho)?;
        next_chirho.phase_chirho = if next_grant_chirho.is_some() {
            Gd7HeldViewTransferPhaseChirho::ReceivingChirho
        } else {
            Gd7HeldViewTransferPhaseChirho::CompleteChirho
        };
        next_chirho.next_page_grant_chirho = next_grant_chirho;
        next_chirho.received_page_count_chirho = received_page_count_chirho;
        next_chirho.received_row_count_chirho = received_row_count_chirho;
        next_chirho.latest_received_page_ref_chirho =
            Some(verified_page_chirho.object_digest_chirho);
        self.commit_checkpoint_chirho(Some(expected_prior_ref_chirho), next_chirho)
    }

    pub fn mark_stale_chirho(
        &self,
        expected_prior_ref_chirho: &str,
        reason_chirho: Gd7HeldViewTransferStaleReasonChirho,
    ) -> Result<CommittedGd7HeldViewTransferChirho, Gd7HeldViewTransferStoreRefusalChirho> {
        let active_chirho = self.load_exact_prior_chirho(expected_prior_ref_chirho)?;
        if matches!(
            active_chirho.checkpoint_chirho.phase_chirho,
            Gd7HeldViewTransferPhaseChirho::CompleteChirho
                | Gd7HeldViewTransferPhaseChirho::StaleChirho
        ) {
            return Err(Gd7HeldViewTransferStoreRefusalChirho::InvalidTransitionChirho);
        }
        let mut next_chirho = active_chirho.checkpoint_chirho;
        advance_checkpoint_coordinate_chirho(&mut next_chirho, expected_prior_ref_chirho)?;
        next_chirho.phase_chirho = Gd7HeldViewTransferPhaseChirho::StaleChirho;
        next_chirho.stale_reason_chirho = Some(reason_chirho);
        self.commit_checkpoint_chirho(Some(expected_prior_ref_chirho), next_chirho)
    }

    fn verify_grant_for_inspection_chirho(
        &self,
        grant_chirho: &Gd7WinnerViewPageGrantChirho,
        inspection_chirho: &Gd7WinnerCurrentViewInspectionChirho,
    ) -> Result<(), Gd7HeldViewTransferStoreRefusalChirho> {
        verify_gd7_winner_view_page_grant_chirho(grant_chirho, self.winner_verifier_chirho)
            .map_err(|_| Gd7HeldViewTransferStoreRefusalChirho::InvalidGrantChirho)?;
        let evidence_chirho = &inspection_chirho.evidence_chirho;
        let root_chirho = &inspection_chirho.bundle_root_chirho;
        if grant_chirho.consistency_group_digest_chirho
            != self.identity_chirho.consistency_group_digest_chirho
            || grant_chirho.held_node_chirho != self.identity_chirho.held_node_chirho
            || grant_chirho.winner_node_chirho != self.identity_chirho.winner_node_chirho
            || grant_chirho.raft_term_chirho != self.identity_chirho.winner_term_chirho
            || grant_chirho.winner_process_generation_chirho
                != evidence_chirho.winner_process_generation_chirho
            || grant_chirho.winner_evidence_object_digest_chirho
                != inspection_chirho.evidence_object_digest_chirho
            || grant_chirho.bundle_root_object_digest_chirho
                != inspection_chirho.bundle_root_object_digest_chirho
            || grant_chirho.source_cut_chirho != root_chirho.source_cut_chirho
        {
            return Err(Gd7HeldViewTransferStoreRefusalChirho::InvalidGrantChirho);
        }
        Ok(())
    }

    fn load_exact_prior_chirho(
        &self,
        expected_prior_ref_chirho: &str,
    ) -> Result<ActiveGd7HeldViewTransferChirho, Gd7HeldViewTransferStoreRefusalChirho> {
        let active_chirho = self
            .load_active_chirho()?
            .ok_or(Gd7HeldViewTransferStoreRefusalChirho::WrongExpectedPriorChirho)?;
        if active_chirho.checkpoint_ref_chirho != expected_prior_ref_chirho {
            return Err(Gd7HeldViewTransferStoreRefusalChirho::WrongExpectedPriorChirho);
        }
        Ok(active_chirho)
    }

    fn commit_checkpoint_chirho(
        &self,
        expected_prior_ref_chirho: Option<&str>,
        mut checkpoint_chirho: Gd7HeldViewTransferCheckpointChirho,
    ) -> Result<CommittedGd7HeldViewTransferChirho, Gd7HeldViewTransferStoreRefusalChirho> {
        if checkpoint_chirho.previous_checkpoint_ref_chirho.as_deref() != expected_prior_ref_chirho
        {
            return Err(Gd7HeldViewTransferStoreRefusalChirho::WrongExpectedPriorChirho);
        }
        checkpoint_chirho.key_id_chirho = self.held_signer_chirho.key_id_chirho();
        checkpoint_chirho.sig_chirho.clear();
        validate_unsigned_checkpoint_chirho(&checkpoint_chirho)?;
        let unsigned_bytes_chirho = canonical_json_chirho(&checkpoint_chirho)
            .map_err(|_| Gd7HeldViewTransferStoreRefusalChirho::SerializationChirho)?;
        let unsigned_line_chirho = std::str::from_utf8(&unsigned_bytes_chirho)
            .map_err(|_| Gd7HeldViewTransferStoreRefusalChirho::SerializationChirho)?;
        checkpoint_chirho.sig_chirho = self
            .held_signer_chirho
            .sign_chirho(unsigned_line_chirho)
            .map_err(|_| Gd7HeldViewTransferStoreRefusalChirho::SigningChirho)?;
        validate_signed_checkpoint_chirho(&checkpoint_chirho)?;
        let checkpoint_bytes_chirho = canonical_json_chirho(&checkpoint_chirho)
            .map_err(|_| Gd7HeldViewTransferStoreRefusalChirho::SerializationChirho)?;
        if checkpoint_bytes_chirho.len() > MAX_GD7_HELD_VIEW_TRANSFER_CHECKPOINT_BYTES_CHIRHO {
            return Err(Gd7HeldViewTransferStoreRefusalChirho::OversizedCheckpointChirho);
        }
        let checkpoint_ref_chirho = digest_bytes_chirho(&checkpoint_bytes_chirho);
        let checkpoint_path_chirho =
            gd7_held_view_transfer_checkpoint_path_chirho(&checkpoint_ref_chirho)?;
        create_exact_chirho(
            self.storage_chirho,
            &checkpoint_path_chirho,
            &checkpoint_bytes_chirho,
            MAX_GD7_HELD_VIEW_TRANSFER_CHECKPOINT_BYTES_CHIRHO,
        )?;

        let active_chirho = self.load_active_chirho()?;
        if active_chirho
            .as_ref()
            .map(|active_chirho| active_chirho.checkpoint_ref_chirho.as_str())
            == Some(checkpoint_ref_chirho.as_str())
        {
            return Ok(CommittedGd7HeldViewTransferChirho {
                checkpoint_ref_chirho,
                checkpoint_chirho,
            });
        }
        let actual_prior_chirho = active_chirho
            .as_ref()
            .map(|active_chirho| active_chirho.checkpoint_ref_chirho.as_str());
        if actual_prior_chirho != expected_prior_ref_chirho {
            return Err(Gd7HeldViewTransferStoreRefusalChirho::WrongExpectedPriorChirho);
        }
        validate_transition_chirho(active_chirho.as_ref(), &checkpoint_chirho)?;

        let head_bytes_chirho =
            self.canonical_signed_head_chirho(&checkpoint_ref_chirho, &checkpoint_chirho)?;
        self.storage_chirho
            .atomic_write_chirho(&self.head_path_chirho, &head_bytes_chirho)
            .map_err(|_| Gd7HeldViewTransferStoreRefusalChirho::StorageChirho)?;
        Ok(CommittedGd7HeldViewTransferChirho {
            checkpoint_ref_chirho,
            checkpoint_chirho,
        })
    }

    fn canonical_signed_head_chirho(
        &self,
        checkpoint_ref_chirho: &str,
        checkpoint_chirho: &Gd7HeldViewTransferCheckpointChirho,
    ) -> Result<Vec<u8>, Gd7HeldViewTransferStoreRefusalChirho> {
        let mut head_chirho = Gd7HeldViewTransferHeadChirho {
            schema_chirho: GD7_HELD_VIEW_TRANSFER_HEAD_SCHEMA_V1_CHIRHO.to_owned(),
            consistency_group_digest_chirho: self
                .identity_chirho
                .consistency_group_digest_chirho
                .clone(),
            reconciliation_checkpoint_ref_chirho: self
                .identity_chirho
                .reconciliation_checkpoint_ref_chirho
                .clone(),
            transfer_identity_digest_chirho: self.identity_digest_chirho.clone(),
            active_checkpoint_ref_chirho: checkpoint_ref_chirho.to_owned(),
            transition_seq_chirho: checkpoint_chirho.transition_seq_chirho,
            phase_chirho: checkpoint_chirho.phase_chirho,
            key_id_chirho: self.held_signer_chirho.key_id_chirho(),
            sig_chirho: String::new(),
        };
        validate_unsigned_head_chirho(
            &head_chirho,
            &self.identity_chirho,
            &self.identity_digest_chirho,
        )?;
        let unsigned_bytes_chirho = canonical_json_chirho(&head_chirho)
            .map_err(|_| Gd7HeldViewTransferStoreRefusalChirho::SerializationChirho)?;
        let unsigned_line_chirho = std::str::from_utf8(&unsigned_bytes_chirho)
            .map_err(|_| Gd7HeldViewTransferStoreRefusalChirho::SerializationChirho)?;
        head_chirho.sig_chirho = self
            .held_signer_chirho
            .sign_chirho(unsigned_line_chirho)
            .map_err(|_| Gd7HeldViewTransferStoreRefusalChirho::SigningChirho)?;
        validate_signed_head_chirho(&head_chirho)?;
        let bytes_chirho = canonical_json_chirho(&head_chirho)
            .map_err(|_| Gd7HeldViewTransferStoreRefusalChirho::SerializationChirho)?;
        if bytes_chirho.len() > MAX_GD7_HELD_VIEW_TRANSFER_HEAD_BYTES_CHIRHO {
            return Err(Gd7HeldViewTransferStoreRefusalChirho::OversizedHeadChirho);
        }
        Ok(bytes_chirho)
    }

    fn parse_and_verify_head_chirho(
        &self,
        bytes_chirho: &[u8],
    ) -> Result<Gd7HeldViewTransferHeadChirho, Gd7HeldViewTransferStoreRefusalChirho> {
        let head_chirho: Gd7HeldViewTransferHeadChirho = serde_json::from_slice(bytes_chirho)
            .map_err(|_| Gd7HeldViewTransferStoreRefusalChirho::MalformedHeadChirho)?;
        validate_unsigned_head_chirho(
            &head_chirho,
            &self.identity_chirho,
            &self.identity_digest_chirho,
        )?;
        validate_signed_head_chirho(&head_chirho)?;
        if canonical_json_chirho(&head_chirho)
            .map_err(|_| Gd7HeldViewTransferStoreRefusalChirho::SerializationChirho)?
            .as_slice()
            != bytes_chirho
        {
            return Err(Gd7HeldViewTransferStoreRefusalChirho::NonCanonicalHeadChirho);
        }
        let mut unsigned_chirho = head_chirho.clone();
        let signature_chirho = std::mem::take(&mut unsigned_chirho.sig_chirho);
        let unsigned_bytes_chirho = canonical_json_chirho(&unsigned_chirho)
            .map_err(|_| Gd7HeldViewTransferStoreRefusalChirho::SerializationChirho)?;
        let unsigned_line_chirho = std::str::from_utf8(&unsigned_bytes_chirho)
            .map_err(|_| Gd7HeldViewTransferStoreRefusalChirho::SerializationChirho)?;
        if !self
            .held_signer_chirho
            .verify_chirho(unsigned_line_chirho, &signature_chirho)
        {
            return Err(Gd7HeldViewTransferStoreRefusalChirho::InvalidHeadSignatureChirho);
        }
        Ok(head_chirho)
    }

    fn parse_and_verify_checkpoint_chirho(
        &self,
        bytes_chirho: &[u8],
    ) -> Result<Gd7HeldViewTransferCheckpointChirho, Gd7HeldViewTransferStoreRefusalChirho> {
        let checkpoint_chirho: Gd7HeldViewTransferCheckpointChirho =
            serde_json::from_slice(bytes_chirho)
                .map_err(|_| Gd7HeldViewTransferStoreRefusalChirho::MalformedCheckpointChirho)?;
        validate_signed_checkpoint_chirho(&checkpoint_chirho)?;
        if checkpoint_chirho.identity_chirho != self.identity_chirho
            || canonical_json_chirho(&checkpoint_chirho)
                .map_err(|_| Gd7HeldViewTransferStoreRefusalChirho::SerializationChirho)?
                .as_slice()
                != bytes_chirho
        {
            return Err(Gd7HeldViewTransferStoreRefusalChirho::NonCanonicalCheckpointChirho);
        }
        let mut unsigned_chirho = checkpoint_chirho.clone();
        let signature_chirho = std::mem::take(&mut unsigned_chirho.sig_chirho);
        let unsigned_bytes_chirho = canonical_json_chirho(&unsigned_chirho)
            .map_err(|_| Gd7HeldViewTransferStoreRefusalChirho::SerializationChirho)?;
        let unsigned_line_chirho = std::str::from_utf8(&unsigned_bytes_chirho)
            .map_err(|_| Gd7HeldViewTransferStoreRefusalChirho::SerializationChirho)?;
        if !self
            .held_signer_chirho
            .verify_chirho(unsigned_line_chirho, &signature_chirho)
        {
            return Err(Gd7HeldViewTransferStoreRefusalChirho::InvalidCheckpointSignatureChirho);
        }
        Ok(checkpoint_chirho)
    }
}

fn active_from_committed_chirho(
    committed_chirho: CommittedGd7HeldViewTransferChirho,
) -> ActiveGd7HeldViewTransferChirho {
    ActiveGd7HeldViewTransferChirho {
        checkpoint_ref_chirho: committed_chirho.checkpoint_ref_chirho,
        checkpoint_chirho: committed_chirho.checkpoint_chirho,
    }
}

fn advance_checkpoint_coordinate_chirho(
    checkpoint_chirho: &mut Gd7HeldViewTransferCheckpointChirho,
    expected_prior_ref_chirho: &str,
) -> Result<(), Gd7HeldViewTransferStoreRefusalChirho> {
    checkpoint_chirho.transition_seq_chirho = checkpoint_chirho
        .transition_seq_chirho
        .checked_add(1)
        .ok_or(Gd7HeldViewTransferStoreRefusalChirho::InvalidTransitionChirho)?;
    checkpoint_chirho.previous_checkpoint_ref_chirho = Some(expected_prior_ref_chirho.to_owned());
    checkpoint_chirho.sig_chirho.clear();
    Ok(())
}

fn validate_identity_chirho(
    identity_chirho: &Gd7HeldViewTransferIdentityChirho,
) -> Result<(), Gd7HeldViewTransferStoreRefusalChirho> {
    if consistency_group_digest_suffix_chirho(&identity_chirho.consistency_group_digest_chirho)
        .is_none()
        || !is_lower_hex_digest_chirho(&identity_chirho.reconciliation_checkpoint_ref_chirho)
        || !is_lower_hex_digest_chirho(&identity_chirho.winner_node_chirho)
        || !is_lower_hex_digest_chirho(&identity_chirho.held_node_chirho)
        || identity_chirho.winner_node_chirho == identity_chirho.held_node_chirho
        || identity_chirho.winner_term_chirho == 0
    {
        return Err(Gd7HeldViewTransferStoreRefusalChirho::InvalidIdentityChirho);
    }
    Ok(())
}

fn validate_unsigned_checkpoint_chirho(
    checkpoint_chirho: &Gd7HeldViewTransferCheckpointChirho,
) -> Result<(), Gd7HeldViewTransferStoreRefusalChirho> {
    validate_identity_chirho(&checkpoint_chirho.identity_chirho)?;
    if checkpoint_chirho.schema_chirho != GD7_HELD_VIEW_TRANSFER_CHECKPOINT_SCHEMA_V1_CHIRHO
        || checkpoint_chirho.key_id_chirho != checkpoint_chirho.identity_chirho.held_node_chirho
        || checkpoint_chirho
            .previous_checkpoint_ref_chirho
            .as_deref()
            .is_some_and(|reference_chirho| !is_lower_hex_digest_chirho(reference_chirho))
        || checkpoint_chirho
            .latest_received_page_ref_chirho
            .as_deref()
            .is_some_and(|reference_chirho| !is_lower_hex_digest_chirho(reference_chirho))
        || checkpoint_chirho
            .canonical_challenge_chirho
            .as_ref()
            .is_some_and(|challenge_chirho| {
                challenge_chirho.len() > MAX_GD7_WINNER_CURRENT_VIEW_CHALLENGE_BYTES_CHIRHO
            })
    {
        return Err(Gd7HeldViewTransferStoreRefusalChirho::InvalidStateChirho);
    }
    let empty_stage_chirho = checkpoint_chirho.canonical_challenge_chirho.is_none()
        && checkpoint_chirho.staged_bundle_root_ref_chirho.is_none()
        && checkpoint_chirho.staged_page_count_chirho.is_none()
        && checkpoint_chirho.staged_row_count_chirho.is_none()
        && checkpoint_chirho.inspection_chirho.is_none()
        && checkpoint_chirho.next_page_grant_chirho.is_none()
        && checkpoint_chirho.received_page_count_chirho == 0
        && checkpoint_chirho.received_row_count_chirho == 0
        && checkpoint_chirho.latest_received_page_ref_chirho.is_none();
    let has_challenge_chirho = checkpoint_chirho.canonical_challenge_chirho.is_some()
        && checkpoint_chirho
            .staged_bundle_root_ref_chirho
            .as_deref()
            .is_some_and(is_lower_hex_digest_chirho)
        && checkpoint_chirho.staged_page_count_chirho.is_some()
        && checkpoint_chirho.staged_row_count_chirho.is_some();
    let valid_phase_shape_chirho = match checkpoint_chirho.phase_chirho {
        Gd7HeldViewTransferPhaseChirho::StagingChirho => {
            empty_stage_chirho && checkpoint_chirho.stale_reason_chirho.is_none()
        }
        Gd7HeldViewTransferPhaseChirho::ChallengeIssuedChirho => {
            has_challenge_chirho
                && checkpoint_chirho.inspection_chirho.is_none()
                && checkpoint_chirho.next_page_grant_chirho.is_none()
                && checkpoint_chirho.received_page_count_chirho == 0
                && checkpoint_chirho.received_row_count_chirho == 0
                && checkpoint_chirho.latest_received_page_ref_chirho.is_none()
                && checkpoint_chirho.stale_reason_chirho.is_none()
        }
        Gd7HeldViewTransferPhaseChirho::ReceivingChirho => {
            has_challenge_chirho
                && checkpoint_chirho.inspection_chirho.is_some()
                && checkpoint_chirho.next_page_grant_chirho.is_some()
                && checkpoint_chirho.stale_reason_chirho.is_none()
        }
        Gd7HeldViewTransferPhaseChirho::CompleteChirho => {
            has_challenge_chirho
                && checkpoint_chirho.inspection_chirho.is_some()
                && checkpoint_chirho.next_page_grant_chirho.is_none()
                && checkpoint_chirho.stale_reason_chirho.is_none()
        }
        Gd7HeldViewTransferPhaseChirho::StaleChirho => {
            checkpoint_chirho.stale_reason_chirho.is_some()
        }
    };
    if !valid_phase_shape_chirho {
        return Err(Gd7HeldViewTransferStoreRefusalChirho::InvalidStateChirho);
    }
    Ok(())
}

fn validate_signed_checkpoint_chirho(
    checkpoint_chirho: &Gd7HeldViewTransferCheckpointChirho,
) -> Result<(), Gd7HeldViewTransferStoreRefusalChirho> {
    validate_unsigned_checkpoint_chirho(checkpoint_chirho)?;
    if !validate_key_and_signature_chirho(
        &checkpoint_chirho.key_id_chirho,
        &checkpoint_chirho.sig_chirho,
    ) {
        return Err(Gd7HeldViewTransferStoreRefusalChirho::InvalidCheckpointSignatureChirho);
    }
    Ok(())
}

fn validate_unsigned_head_chirho(
    head_chirho: &Gd7HeldViewTransferHeadChirho,
    identity_chirho: &Gd7HeldViewTransferIdentityChirho,
    identity_digest_chirho: &str,
) -> Result<(), Gd7HeldViewTransferStoreRefusalChirho> {
    if head_chirho.schema_chirho != GD7_HELD_VIEW_TRANSFER_HEAD_SCHEMA_V1_CHIRHO
        || head_chirho.consistency_group_digest_chirho
            != identity_chirho.consistency_group_digest_chirho
        || head_chirho.reconciliation_checkpoint_ref_chirho
            != identity_chirho.reconciliation_checkpoint_ref_chirho
        || head_chirho.transfer_identity_digest_chirho != identity_digest_chirho
        || !is_lower_hex_digest_chirho(&head_chirho.active_checkpoint_ref_chirho)
        || head_chirho.key_id_chirho != identity_chirho.held_node_chirho
    {
        return Err(Gd7HeldViewTransferStoreRefusalChirho::InvalidStateChirho);
    }
    Ok(())
}

fn validate_signed_head_chirho(
    head_chirho: &Gd7HeldViewTransferHeadChirho,
) -> Result<(), Gd7HeldViewTransferStoreRefusalChirho> {
    if !validate_key_and_signature_chirho(&head_chirho.key_id_chirho, &head_chirho.sig_chirho) {
        return Err(Gd7HeldViewTransferStoreRefusalChirho::InvalidHeadSignatureChirho);
    }
    Ok(())
}

fn validate_transition_chirho(
    active_chirho: Option<&ActiveGd7HeldViewTransferChirho>,
    next_chirho: &Gd7HeldViewTransferCheckpointChirho,
) -> Result<(), Gd7HeldViewTransferStoreRefusalChirho> {
    let Some(active_chirho) = active_chirho else {
        if next_chirho.phase_chirho == Gd7HeldViewTransferPhaseChirho::StagingChirho
            && next_chirho.transition_seq_chirho == 0
            && next_chirho.previous_checkpoint_ref_chirho.is_none()
        {
            return Ok(());
        }
        return Err(Gd7HeldViewTransferStoreRefusalChirho::InvalidTransitionChirho);
    };
    let prior_chirho = &active_chirho.checkpoint_chirho;
    if next_chirho.identity_chirho != prior_chirho.identity_chirho
        || next_chirho.previous_checkpoint_ref_chirho.as_deref()
            != Some(active_chirho.checkpoint_ref_chirho.as_str())
        || prior_chirho.transition_seq_chirho.checked_add(1)
            != Some(next_chirho.transition_seq_chirho)
        || next_chirho.expected_stage_index_chirho < prior_chirho.expected_stage_index_chirho
        || next_chirho.received_page_count_chirho < prior_chirho.received_page_count_chirho
        || next_chirho.received_row_count_chirho < prior_chirho.received_row_count_chirho
    {
        return Err(Gd7HeldViewTransferStoreRefusalChirho::InvalidTransitionChirho);
    }
    let phase_valid_chirho = matches!(
        (prior_chirho.phase_chirho, next_chirho.phase_chirho),
        (
            Gd7HeldViewTransferPhaseChirho::StagingChirho,
            Gd7HeldViewTransferPhaseChirho::StagingChirho
        ) | (
            Gd7HeldViewTransferPhaseChirho::StagingChirho,
            Gd7HeldViewTransferPhaseChirho::ChallengeIssuedChirho
        ) | (
            Gd7HeldViewTransferPhaseChirho::ChallengeIssuedChirho,
            Gd7HeldViewTransferPhaseChirho::ReceivingChirho
                | Gd7HeldViewTransferPhaseChirho::CompleteChirho
        ) | (
            Gd7HeldViewTransferPhaseChirho::ReceivingChirho,
            Gd7HeldViewTransferPhaseChirho::ReceivingChirho
                | Gd7HeldViewTransferPhaseChirho::CompleteChirho
        ) | (
            Gd7HeldViewTransferPhaseChirho::StagingChirho
                | Gd7HeldViewTransferPhaseChirho::ChallengeIssuedChirho
                | Gd7HeldViewTransferPhaseChirho::ReceivingChirho,
            Gd7HeldViewTransferPhaseChirho::StaleChirho
        )
    );
    if !phase_valid_chirho {
        return Err(Gd7HeldViewTransferStoreRefusalChirho::InvalidTransitionChirho);
    }
    Ok(())
}

fn digest_sharded_path_chirho(
    family_chirho: &str,
    object_digest_chirho: &str,
) -> Result<StoragePathChirho, Gd7HeldViewTransferStoreRefusalChirho> {
    if !is_lower_hex_digest_chirho(object_digest_chirho) {
        return Err(Gd7HeldViewTransferStoreRefusalChirho::InvalidIdentityChirho);
    }
    Ok(StoragePathChirho::new_chirho(format!(
        "{GD7_RECONCILIATION_NAMESPACE_CHIRHO}/{family_chirho}/{}/{}/{object_digest_chirho}.json",
        &object_digest_chirho[..2],
        &object_digest_chirho[2..4],
    )))
}

fn read_bounded_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    path_chirho: &StoragePathChirho,
    maximum_chirho: usize,
    oversized_chirho: Gd7HeldViewTransferStoreRefusalChirho,
) -> Result<Option<Vec<u8>>, Gd7HeldViewTransferStoreRefusalChirho> {
    let Some(length_chirho) = storage_chirho
        .object_len_chirho(path_chirho)
        .map_err(|_| Gd7HeldViewTransferStoreRefusalChirho::StorageChirho)?
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
            .map_err(|_| Gd7HeldViewTransferStoreRefusalChirho::StorageChirho)?
    };
    if bytes_chirho.len() != length_chirho as usize
        || storage_chirho
            .object_len_chirho(path_chirho)
            .map_err(|_| Gd7HeldViewTransferStoreRefusalChirho::StorageChirho)?
            != Some(length_chirho)
    {
        return Err(Gd7HeldViewTransferStoreRefusalChirho::StorageChirho);
    }
    Ok(Some(bytes_chirho))
}

fn create_exact_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    path_chirho: &StoragePathChirho,
    bytes_chirho: &[u8],
    maximum_chirho: usize,
) -> Result<(), Gd7HeldViewTransferStoreRefusalChirho> {
    if bytes_chirho.len() > maximum_chirho {
        return Err(Gd7HeldViewTransferStoreRefusalChirho::InvalidStateChirho);
    }
    match storage_chirho
        .create_durable_chirho(path_chirho, bytes_chirho)
        .map_err(|_| Gd7HeldViewTransferStoreRefusalChirho::StorageChirho)?
    {
        CreateDurableOutcomeChirho::CreatedChirho => Ok(()),
        CreateDurableOutcomeChirho::AlreadyExistsChirho => {
            let existing_chirho = read_bounded_chirho(
                storage_chirho,
                path_chirho,
                maximum_chirho,
                Gd7HeldViewTransferStoreRefusalChirho::ImmutableCollisionChirho,
            )?
            .ok_or(Gd7HeldViewTransferStoreRefusalChirho::ImmutableCollisionChirho)?;
            if existing_chirho == bytes_chirho {
                Ok(())
            } else {
                Err(Gd7HeldViewTransferStoreRefusalChirho::ImmutableCollisionChirho)
            }
        }
    }
}
