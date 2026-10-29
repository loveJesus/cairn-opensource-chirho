// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Fresh-challenge, O(1)-addressed evidence for one elected winner's exact current view.
//!
//! Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/cf8-gd7-deposed-fork-reconciliation-design-chirho.md`.
//! This module creates and verifies evidence only. It cannot move a served ref, authorize
//! compensation, adopt a bundle, converge a held node, or re-enable writes.

use super::contract_chirho::{
    consistency_group_digest_suffix_chirho, is_lower_hex_digest_chirho, validate_identity_chirho,
    validate_key_and_signature_chirho, Gd7JournalTailCoordinateChirho,
    Gd7ReconciliationSignerPortChirho, Gd7ReconciliationVerifierPortChirho,
};
use cairn_ledger_log_chirho::losing_suffix_chirho::VerifiedLosingJournalTailChirho;
use cairn_ledger_log_chirho::ports_chirho::{
    CreateDurableOutcomeChirho, LedgerStoragePortChirho, StoragePathChirho,
};
use cairn_ledger_model_chirho::ids_chirho::AccountIdChirho;
use cairn_ledger_read_model_chirho::{
    account_net_projection_fold_ref_chirho, AccountNetProjectionPageSliceChirho,
};
use cairn_writer_elector_chirho::elector_port_chirho::{NodeIdChirho, WriterElectorChirho};
use cairn_writer_elector_chirho::{
    LocalAppendAuthorityHandleChirho, LocalAppendAuthorityRefusalChirho,
    LocalAppendHandoffPreparationChirho,
};
use cairn_writer_head_chirho::writer_head_chirho::{
    consistency_group_digest_chirho, split_writer_epoch_chirho, ConsistencyGroupIdChirho,
    WRITER_EPOCH_COMPONENT_MAX_CHIRHO,
};
use rand_core::{OsRng, RngCore};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::error::Error;
use std::fmt;

#[path = "current_view_chirho/adoption_chirho.rs"]
mod adoption_chirho;
#[path = "current_view_chirho/bundle_chirho.rs"]
mod bundle_chirho;
#[path = "current_view_chirho/fork_baseline_chirho.rs"]
mod fork_baseline_chirho;
#[path = "current_view_chirho/held_evidence_transfer_chirho/mod.rs"]
mod held_evidence_transfer_chirho;
#[path = "current_view_chirho/held_transfer_chirho.rs"]
mod held_transfer_chirho;
#[path = "current_view_chirho/transfer_chirho.rs"]
mod transfer_chirho;
#[path = "current_view_chirho/winner_handoff_chirho.rs"]
mod winner_handoff_chirho;
#[path = "current_view_chirho/winner_history_chirho.rs"]
mod winner_history_chirho;

pub use adoption_chirho::{
    verify_complete_gd7_held_winner_view_chain_chirho,
    verify_fresh_gd7_held_winner_view_evidence_chirho, Gd7HeldWinnerViewVerificationRefusalChirho,
    VerifiedGd7HeldWinnerViewChainChirho, VerifiedGd7HeldWinnerViewFreshnessEvidenceChirho,
};
pub use bundle_chirho::{Gd7WinnerViewBundleRestartChirho, Gd7WinnerViewBundleStageOutcomeChirho};
pub use fork_baseline_chirho::{
    gd7_fork_baseline_page_path_chirho, gd7_fork_baseline_root_path_chirho,
    load_verified_gd7_fork_baseline_root_chirho, verify_complete_gd7_fork_baseline_chirho,
    Gd7ForkBaselineIdentityChirho, Gd7ForkBaselineRefusalChirho, Gd7ForkBaselineRootChirho,
    VerifiedGd7ForkBaselineChirho, VerifiedGd7ForkBaselineRootChirho,
    GD7_FORK_BASELINE_PAGE_ROWS_CHIRHO, GD7_FORK_BASELINE_ROOT_SCHEMA_V1_CHIRHO,
    MAX_GD7_FORK_BASELINE_PAGE_BYTES_CHIRHO, MAX_GD7_FORK_BASELINE_ROOT_BYTES_CHIRHO,
};
pub use held_evidence_transfer_chirho::{
    build_gd7_winner_evidence_manifest_chirho, fetch_gd7_winner_evidence_page_chirho,
    gd7_held_evidence_transfer_checkpoint_path_chirho, gd7_held_evidence_transfer_head_path_chirho,
    gd7_held_evidence_transfer_identity_digest_chirho, gd7_read_only_branch_checkpoint_path_chirho,
    gd7_read_only_branch_head_path_chirho, gd7_read_only_branch_prefix_page_path_chirho,
    gd7_read_only_branch_prefix_root_path_chirho, verify_gd7_winner_evidence_manifest_chirho,
    verify_gd7_winner_evidence_page_transfer_chirho, ActiveGd7HeldEvidenceTransferChirho,
    ActiveGd7ReadOnlyBranchChirho, Gd7AccountNetCompositionRefusalChirho,
    Gd7HeldEvidenceTransferCheckpointChirho, Gd7HeldEvidenceTransferHeadChirho,
    Gd7HeldEvidenceTransferIdentityChirho, Gd7HeldEvidenceTransferPhaseChirho,
    Gd7HeldEvidenceTransferStoreChirho, Gd7HeldEvidenceTransferStoreRefusalChirho,
    Gd7ReadOnlyBranchCheckpointChirho, Gd7ReadOnlyBranchHeadChirho,
    Gd7ReadOnlyBranchPrefixRootChirho, Gd7ReadOnlyBranchRefusalChirho,
    Gd7WinnerEvidenceFamilyChirho, Gd7WinnerEvidenceManifestChirho,
    Gd7WinnerEvidencePageGrantChirho, Gd7WinnerEvidencePageTransferChirho,
    Gd7WinnerEvidenceTransferRefusalChirho, PreparedGd7ReadOnlyBranchChirho,
    VerifiedGd7AccountNetCompositionChirho, VerifiedGd7ReadOnlyBranchChirho,
    GD7_HELD_EVIDENCE_TRANSFER_CHECKPOINT_SCHEMA_V1_CHIRHO,
    GD7_HELD_EVIDENCE_TRANSFER_HEAD_SCHEMA_V1_CHIRHO,
    GD7_READ_ONLY_BRANCH_CHECKPOINT_SCHEMA_V1_CHIRHO, GD7_READ_ONLY_BRANCH_HEAD_SCHEMA_V1_CHIRHO,
    GD7_READ_ONLY_BRANCH_PREFIX_ROOT_SCHEMA_V1_CHIRHO,
    GD7_WINNER_EVIDENCE_MANIFEST_SCHEMA_V1_CHIRHO, GD7_WINNER_EVIDENCE_PAGE_GRANT_SCHEMA_V1_CHIRHO,
    MAX_GD7_HELD_EVIDENCE_TRANSFER_CHECKPOINT_BYTES_CHIRHO,
    MAX_GD7_HELD_EVIDENCE_TRANSFER_HEAD_BYTES_CHIRHO,
    MAX_GD7_READ_ONLY_BRANCH_CHECKPOINT_BYTES_CHIRHO, MAX_GD7_READ_ONLY_BRANCH_HEAD_BYTES_CHIRHO,
    MAX_GD7_READ_ONLY_BRANCH_PREFIX_PAGE_BYTES_CHIRHO,
    MAX_GD7_READ_ONLY_BRANCH_PREFIX_ROOT_BYTES_CHIRHO,
    MAX_GD7_WINNER_EVIDENCE_MANIFEST_BYTES_CHIRHO, MAX_GD7_WINNER_EVIDENCE_PAGE_GRANT_BYTES_CHIRHO,
};
pub use held_transfer_chirho::{
    gd7_held_view_transfer_checkpoint_path_chirho, gd7_held_view_transfer_head_path_chirho,
    gd7_held_view_transfer_received_page_path_chirho,
    verify_complete_gd7_held_view_transfer_checkpoint_chirho, ActiveGd7HeldViewTransferChirho,
    CommittedGd7HeldViewTransferChirho, Gd7HeldViewTransferCheckpointChirho,
    Gd7HeldViewTransferHeadChirho, Gd7HeldViewTransferIdentityChirho,
    Gd7HeldViewTransferPhaseChirho, Gd7HeldViewTransferStaleReasonChirho,
    Gd7HeldViewTransferStoreChirho, Gd7HeldViewTransferStoreRefusalChirho,
    GD7_HELD_VIEW_TRANSFER_CHECKPOINT_SCHEMA_V1_CHIRHO,
    GD7_HELD_VIEW_TRANSFER_HEAD_SCHEMA_V1_CHIRHO,
    MAX_GD7_HELD_VIEW_TRANSFER_CHECKPOINT_BYTES_CHIRHO,
    MAX_GD7_HELD_VIEW_TRANSFER_HEAD_BYTES_CHIRHO,
};
pub(crate) use transfer_chirho::{
    fetch_granted_gd7_winner_view_page_chirho, issue_first_gd7_winner_view_page_grant_chirho,
    Gd7WinnerViewPageFetchContextChirho,
};
pub use transfer_chirho::{
    Gd7WinnerViewPageGrantChirho, Gd7WinnerViewPageTransferChirho,
    GD7_WINNER_VIEW_PAGE_GRANT_SCHEMA_V1_CHIRHO, MAX_GD7_WINNER_VIEW_PAGE_GRANT_BYTES_CHIRHO,
};
pub use winner_handoff_chirho::{
    gd7_winner_handoff_attempt_digest_chirho, gd7_winner_handoff_checkpoint_path_chirho,
    gd7_winner_handoff_head_path_chirho, ActiveGd7WinnerHandoffChirho,
    CommittedGd7WinnerHandoffChirho, Gd7WinnerHandoffAttemptIdentityChirho,
    Gd7WinnerHandoffCheckpointChirho, Gd7WinnerHandoffCommitOutcomeChirho,
    Gd7WinnerHandoffHeadChirho, Gd7WinnerHandoffPhaseChirho, Gd7WinnerHandoffStoreChirho,
    Gd7WinnerHandoffStoreRefusalChirho, GD7_WINNER_HANDOFF_CHECKPOINT_SCHEMA_V1_CHIRHO,
    GD7_WINNER_HANDOFF_HEAD_SCHEMA_V1_CHIRHO, MAX_GD7_WINNER_HANDOFF_CHECKPOINT_BYTES_CHIRHO,
    MAX_GD7_WINNER_HANDOFF_HEAD_BYTES_CHIRHO,
};
pub use winner_history_chirho::{
    gd7_winner_history_cursor_path_chirho, gd7_winner_history_page_path_chirho,
    gd7_winner_history_root_path_chirho, load_verified_gd7_winner_history_root_chirho,
    verify_complete_gd7_winner_history_chain_chirho, Gd7WinnerHistoryIdentityChirho,
    Gd7WinnerHistoryRefusalChirho, Gd7WinnerHistoryRestartChirho, Gd7WinnerHistoryRootChirho,
    Gd7WinnerHistoryStageOutcomeChirho, VerifiedGd7WinnerHistoryChainChirho,
    VerifiedGd7WinnerHistoryRootChirho, GD7_WINNER_HISTORY_ROOT_SCHEMA_V1_CHIRHO,
    MAX_GD7_WINNER_HISTORY_PAGE_BYTES_CHIRHO, MAX_GD7_WINNER_HISTORY_ROOT_BYTES_CHIRHO,
};

const GD7_RECONCILIATION_NAMESPACE_CHIRHO: &str = "gd7-reconciliation-chirho";
pub const GD7_WINNER_CURRENT_VIEW_CHALLENGE_SCHEMA_V1_CHIRHO: &str =
    "gd7-winner-current-view-challenge-v1-chirho";
pub const GD7_WINNER_CURRENT_VIEW_EVIDENCE_SCHEMA_V1_CHIRHO: &str =
    "gd7-winner-current-view-evidence-v1-chirho";
pub const GD7_WINNER_VIEW_BUNDLE_ROOT_SCHEMA_V1_CHIRHO: &str =
    "gd7-winner-view-bundle-root-v1-chirho";
pub const MAX_GD7_WINNER_CURRENT_VIEW_CHALLENGE_BYTES_CHIRHO: usize = 4 * 1024;
pub const MAX_GD7_WINNER_CURRENT_VIEW_EVIDENCE_BYTES_CHIRHO: usize = 16 * 1024;
pub const MAX_GD7_WINNER_VIEW_BUNDLE_ROOT_BYTES_CHIRHO: usize = 8 * 1024;
pub const MAX_GD7_WINNER_VIEW_BUNDLE_PAGE_BYTES_CHIRHO: usize = 256 * 1024;

/// Canonical transport form of one verifier challenge.
///
/// Parsing this type does not establish freshness. Only the opaque issued wrapper minted locally
/// by `generate_gd7_winner_current_view_challenge_chirho` may enter held-side verification.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gd7WinnerCurrentViewChallengeChirho {
    schema_chirho: String,
    nonce_chirho: String,
    consistency_group_digest_chirho: String,
    expected_winner_node_chirho: String,
    held_node_chirho: String,
    transfer_identity_digest_chirho: String,
    raft_term_chirho: u64,
}

impl Gd7WinnerCurrentViewChallengeChirho {
    pub fn canonical_bytes_chirho(&self) -> Result<Vec<u8>, Gd7WinnerCurrentViewRefusalChirho> {
        validate_challenge_chirho(self)?;
        let bytes_chirho = canonical_json_chirho(self)?;
        if bytes_chirho.len() > MAX_GD7_WINNER_CURRENT_VIEW_CHALLENGE_BYTES_CHIRHO {
            return Err(Gd7WinnerCurrentViewRefusalChirho::OversizedChallengeChirho);
        }
        Ok(bytes_chirho)
    }

    pub fn digest_chirho(&self) -> Result<String, Gd7WinnerCurrentViewRefusalChirho> {
        Ok(digest_bytes_chirho(&self.canonical_bytes_chirho()?))
    }

    pub fn consistency_group_digest_chirho(&self) -> &str {
        &self.consistency_group_digest_chirho
    }

    pub fn expected_winner_node_chirho(&self) -> &str {
        &self.expected_winner_node_chirho
    }

    pub fn held_node_chirho(&self) -> &str {
        &self.held_node_chirho
    }

    pub fn transfer_identity_digest_chirho(&self) -> &str {
        &self.transfer_identity_digest_chirho
    }

    pub fn raft_term_chirho(&self) -> u64 {
        self.raft_term_chirho
    }
}

/// One locally issued, one-use challenge whose constructor is not available to transport peers.
///
/// This type is deliberately neither `Clone` nor deserializable. A held verifier retains it while
/// sending only `canonical_bytes_chirho()` to the winner, then consumes it during verification.
pub struct IssuedGd7WinnerCurrentViewChallengeChirho {
    challenge_chirho: Gd7WinnerCurrentViewChallengeChirho,
}

impl IssuedGd7WinnerCurrentViewChallengeChirho {
    pub fn canonical_bytes_chirho(&self) -> Result<Vec<u8>, Gd7WinnerCurrentViewRefusalChirho> {
        self.challenge_chirho.canonical_bytes_chirho()
    }

    fn into_challenge_chirho(self) -> Gd7WinnerCurrentViewChallengeChirho {
        self.challenge_chirho
    }
}

/// Constant-size content-addressed root for a bounded account-net page chain.
///
/// The current-view verifier rehashes this root and checks its source cut without walking pages.
/// A later adoption verifier must still verify the complete page chain before moving any ref.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gd7WinnerViewBundleRootChirho {
    pub schema_chirho: String,
    pub consistency_group_digest_chirho: String,
    pub projection_fold_ref_chirho: String,
    pub winner_journal_genesis_digest_chirho: String,
    pub source_cut_chirho: Gd7JournalTailCoordinateChirho,
    pub lowest_page_ref_chirho: Option<String>,
    pub page_count_chirho: u64,
    pub row_count_chirho: u64,
}

/// Opaque proof that a bundle stager wrote and reloaded one exact root object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedGd7WinnerViewBundleRootChirho {
    object_digest_chirho: String,
    root_chirho: Gd7WinnerViewBundleRootChirho,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Gd7WinnerJournalSnapshotChirho {
    genesis_digest_chirho: String,
    cut_chirho: Gd7JournalTailCoordinateChirho,
}

impl Gd7WinnerJournalSnapshotChirho {
    pub(crate) fn from_verified_tail_chirho(tail_chirho: VerifiedLosingJournalTailChirho) -> Self {
        Self {
            genesis_digest_chirho: tail_chirho
                .identity_chirho()
                .genesis_digest_chirho()
                .0
                .clone(),
            cut_chirho: Gd7JournalTailCoordinateChirho {
                epoch_chirho: tail_chirho.record_epoch_chirho(),
                seq_chirho: tail_chirho.coordinate_chirho().seq_chirho(),
                record_digest_chirho: tail_chirho
                    .coordinate_chirho()
                    .record_digest_chirho()
                    .0
                    .clone(),
            },
        }
    }
}

impl VerifiedGd7WinnerViewBundleRootChirho {
    pub fn object_digest_chirho(&self) -> &str {
        &self.object_digest_chirho
    }

    pub fn root_chirho(&self) -> &Gd7WinnerViewBundleRootChirho {
        &self.root_chirho
    }
}

/// Winner-signed response to one exact challenge and one exact staged view root.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gd7WinnerCurrentViewEvidenceChirho {
    pub schema_chirho: String,
    pub challenge_digest_chirho: String,
    pub consistency_group_digest_chirho: String,
    pub winner_node_chirho: String,
    pub raft_term_chirho: u64,
    pub winner_process_generation_chirho: u64,
    pub winner_journal_genesis_digest_chirho: String,
    pub latest_verified_journal_cut_chirho: Gd7JournalTailCoordinateChirho,
    pub view_bundle_root_chirho: String,
    pub key_id_chirho: String,
    pub sig_chirho: String,
}

/// Opaque, challenged proof accepted under stable held-node election observations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct VerifiedGd7WinnerCurrentViewEvidenceChirho {
    object_digest_chirho: String,
    evidence_chirho: Gd7WinnerCurrentViewEvidenceChirho,
    bundle_root_chirho: VerifiedGd7WinnerViewBundleRootChirho,
}

impl VerifiedGd7WinnerCurrentViewEvidenceChirho {
    pub(crate) fn into_inspection_chirho(self) -> Gd7WinnerCurrentViewInspectionChirho {
        Gd7WinnerCurrentViewInspectionChirho {
            evidence_object_digest_chirho: self.object_digest_chirho,
            evidence_chirho: self.evidence_chirho,
            bundle_root_object_digest_chirho: self.bundle_root_chirho.object_digest_chirho,
            bundle_root_chirho: self.bundle_root_chirho.root_chirho,
        }
    }
}

/// Constructible diagnostic report verified under the caller's explicitly supplied trust roots.
///
/// This is deliberately not an authority token. Adoption must use the crate-private proof inside
/// the resident multi-node actor and recheck the real authenticated elector immediately before a
/// ref move.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gd7WinnerCurrentViewInspectionChirho {
    pub evidence_object_digest_chirho: String,
    pub evidence_chirho: Gd7WinnerCurrentViewEvidenceChirho,
    pub bundle_root_object_digest_chirho: String,
    pub bundle_root_chirho: Gd7WinnerViewBundleRootChirho,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants must carry the Chirho suffix"
)]
pub enum Gd7WinnerCurrentViewRefusalChirho {
    InvalidChallengeChirho,
    OversizedChallengeChirho,
    ChallengeEntropyUnavailableChirho,
    LeadershipUnavailableChirho,
    LeadershipChangedChirho,
    ResidentEvidenceChangedChirho,
    LocalAuthorityChirho(LocalAppendAuthorityRefusalChirho),
    InvalidCoordinateChirho,
    InvalidBundleRootChirho,
    InvalidBundlePageChirho,
    InvalidPageGrantChirho,
    StageIndexMismatchChirho,
    BundleRootMismatchChirho,
    JournalCutMismatchChirho,
    MissingEvidenceChirho,
    MissingBundleRootChirho,
    MissingBundlePageChirho,
    OversizedEvidenceChirho,
    OversizedBundleRootChirho,
    OversizedBundlePageChirho,
    MalformedEvidenceChirho,
    MalformedBundleRootChirho,
    MalformedBundlePageChirho,
    NonCanonicalEvidenceChirho,
    NonCanonicalBundleRootChirho,
    NonCanonicalBundlePageChirho,
    ObjectDigestMismatchChirho,
    ProjectionChirho,
    WrongSignerChirho,
    InvalidSignatureChirho,
    ImmutableCollisionChirho,
    SerializationChirho,
    SigningChirho,
    StorageChirho,
}

impl fmt::Display for Gd7WinnerCurrentViewRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidChallengeChirho => {
                formatter_chirho.write_str("GD7 winner current-view challenge is invalid")
            }
            Self::OversizedChallengeChirho => {
                formatter_chirho.write_str("GD7 winner current-view challenge exceeds its bound")
            }
            Self::ChallengeEntropyUnavailableChirho => formatter_chirho
                .write_str("GD7 winner current-view challenge entropy is unavailable"),
            Self::LeadershipUnavailableChirho => {
                formatter_chirho.write_str("GD7 current elected winner is unavailable")
            }
            Self::LeadershipChangedChirho => formatter_chirho
                .write_str("GD7 elected winner changed during current-view verification"),
            Self::ResidentEvidenceChangedChirho => formatter_chirho
                .write_str("GD7 winner resident evidence changed before current-view sealing"),
            Self::LocalAuthorityChirho(error_chirho) => {
                write!(
                    formatter_chirho,
                    "GD7 local winner authority refused: {error_chirho}"
                )
            }
            Self::InvalidCoordinateChirho => {
                formatter_chirho.write_str("GD7 current-view coordinate is invalid")
            }
            Self::InvalidBundleRootChirho => {
                formatter_chirho.write_str("GD7 winner view-bundle root is invalid")
            }
            Self::InvalidBundlePageChirho => {
                formatter_chirho.write_str("GD7 winner view-bundle page is invalid")
            }
            Self::InvalidPageGrantChirho => {
                formatter_chirho.write_str("GD7 winner view-page grant is invalid")
            }
            Self::StageIndexMismatchChirho => {
                formatter_chirho.write_str("GD7 winner view staging index differs from actor state")
            }
            Self::BundleRootMismatchChirho => formatter_chirho
                .write_str("GD7 winner view-bundle root differs from its challenged evidence"),
            Self::JournalCutMismatchChirho => formatter_chirho
                .write_str("GD7 winner journal cut differs from the staged view bundle"),
            Self::MissingEvidenceChirho => {
                formatter_chirho.write_str("GD7 winner current-view evidence is missing")
            }
            Self::MissingBundleRootChirho => {
                formatter_chirho.write_str("GD7 winner view-bundle root is missing")
            }
            Self::MissingBundlePageChirho => {
                formatter_chirho.write_str("GD7 winner view-bundle page is missing")
            }
            Self::OversizedEvidenceChirho => {
                formatter_chirho.write_str("GD7 winner current-view evidence exceeds its bound")
            }
            Self::OversizedBundleRootChirho => {
                formatter_chirho.write_str("GD7 winner view-bundle root exceeds its bound")
            }
            Self::OversizedBundlePageChirho => {
                formatter_chirho.write_str("GD7 winner view-bundle page exceeds its bound")
            }
            Self::MalformedEvidenceChirho => {
                formatter_chirho.write_str("GD7 winner current-view evidence is malformed")
            }
            Self::MalformedBundleRootChirho => {
                formatter_chirho.write_str("GD7 winner view-bundle root is malformed")
            }
            Self::MalformedBundlePageChirho => {
                formatter_chirho.write_str("GD7 winner view-bundle page is malformed")
            }
            Self::NonCanonicalEvidenceChirho => {
                formatter_chirho.write_str("GD7 winner current-view evidence is not canonical")
            }
            Self::NonCanonicalBundleRootChirho => {
                formatter_chirho.write_str("GD7 winner view-bundle root is not canonical")
            }
            Self::NonCanonicalBundlePageChirho => {
                formatter_chirho.write_str("GD7 winner view-bundle page is not canonical")
            }
            Self::ObjectDigestMismatchChirho => {
                formatter_chirho.write_str("GD7 content-addressed object digest does not match")
            }
            Self::ProjectionChirho => {
                formatter_chirho.write_str("GD7 bounded winner projection refused")
            }
            Self::WrongSignerChirho => {
                formatter_chirho.write_str("GD7 current-view signer is not the elected winner")
            }
            Self::InvalidSignatureChirho => {
                formatter_chirho.write_str("GD7 winner current-view signature is invalid")
            }
            Self::ImmutableCollisionChirho => {
                formatter_chirho.write_str("GD7 immutable current-view evidence collided")
            }
            Self::SerializationChirho => {
                formatter_chirho.write_str("GD7 current-view serialization failed")
            }
            Self::SigningChirho => formatter_chirho.write_str("GD7 current-view signing failed"),
            Self::StorageChirho => {
                formatter_chirho.write_str("GD7 current-view storage operation failed")
            }
        }
    }
}

impl Error for Gd7WinnerCurrentViewRefusalChirho {}

/// Mint a fresh challenge from the held node's current elected-winner observation.
pub fn generate_gd7_winner_current_view_challenge_chirho<
    ElectorChirho: WriterElectorChirho + ?Sized,
>(
    elector_chirho: &ElectorChirho,
    group_chirho: &ConsistencyGroupIdChirho,
    expected_winner_chirho: &NodeIdChirho,
    held_node_chirho: &NodeIdChirho,
    transfer_identity_digest_chirho: &str,
) -> Result<IssuedGd7WinnerCurrentViewChallengeChirho, Gd7WinnerCurrentViewRefusalChirho> {
    let leadership_chirho =
        observe_expected_winner_chirho(elector_chirho, group_chirho, expected_winner_chirho)?;
    let group_digest_chirho = consistency_group_digest_chirho(group_chirho)
        .map_err(|_| Gd7WinnerCurrentViewRefusalChirho::InvalidCoordinateChirho)?;
    let mut nonce_bytes_chirho = [0_u8; 32];
    OsRng
        .try_fill_bytes(&mut nonce_bytes_chirho)
        .map_err(|_| Gd7WinnerCurrentViewRefusalChirho::ChallengeEntropyUnavailableChirho)?;
    let challenge_chirho = Gd7WinnerCurrentViewChallengeChirho {
        schema_chirho: GD7_WINNER_CURRENT_VIEW_CHALLENGE_SCHEMA_V1_CHIRHO.to_owned(),
        nonce_chirho: lower_hex_chirho(&nonce_bytes_chirho),
        consistency_group_digest_chirho: group_digest_chirho,
        expected_winner_node_chirho: expected_winner_chirho.0.clone(),
        held_node_chirho: held_node_chirho.0.clone(),
        transfer_identity_digest_chirho: transfer_identity_digest_chirho.to_owned(),
        raft_term_chirho: leadership_chirho.term_chirho,
    };
    validate_challenge_chirho(&challenge_chirho)?;
    Ok(IssuedGd7WinnerCurrentViewChallengeChirho { challenge_chirho })
}

pub fn parse_canonical_gd7_winner_current_view_challenge_chirho(
    bytes_chirho: &[u8],
) -> Result<Gd7WinnerCurrentViewChallengeChirho, Gd7WinnerCurrentViewRefusalChirho> {
    if bytes_chirho.len() > MAX_GD7_WINNER_CURRENT_VIEW_CHALLENGE_BYTES_CHIRHO {
        return Err(Gd7WinnerCurrentViewRefusalChirho::OversizedChallengeChirho);
    }
    let challenge_chirho: Gd7WinnerCurrentViewChallengeChirho =
        serde_json::from_slice(bytes_chirho)
            .map_err(|_| Gd7WinnerCurrentViewRefusalChirho::InvalidChallengeChirho)?;
    validate_challenge_chirho(&challenge_chirho)?;
    if canonical_json_chirho(&challenge_chirho)?.as_slice() != bytes_chirho {
        return Err(Gd7WinnerCurrentViewRefusalChirho::InvalidChallengeChirho);
    }
    Ok(challenge_chirho)
}

/// Exact-address reader used by a held node to verify one challenged winner response.
pub(crate) struct Gd7WinnerCurrentViewReaderChirho<'ports_chirho> {
    storage_chirho: &'ports_chirho dyn LedgerStoragePortChirho,
    winner_verifier_chirho: &'ports_chirho dyn Gd7ReconciliationVerifierPortChirho,
}

impl<'ports_chirho> Gd7WinnerCurrentViewReaderChirho<'ports_chirho> {
    pub(crate) fn new_chirho(
        storage_chirho: &'ports_chirho dyn LedgerStoragePortChirho,
        winner_verifier_chirho: &'ports_chirho dyn Gd7ReconciliationVerifierPortChirho,
    ) -> Self {
        Self {
            storage_chirho,
            winner_verifier_chirho,
        }
    }

    /// Verify a fresh response between two stable held-node election observations.
    ///
    /// This returns evidence only. Adoption must repeat election and checkpoint freshness checks
    /// immediately before any ref movement.
    pub(crate) fn verify_challenged_chirho<ElectorChirho: WriterElectorChirho + ?Sized>(
        &self,
        elector_chirho: &ElectorChirho,
        group_chirho: &ConsistencyGroupIdChirho,
        expected_winner_chirho: &NodeIdChirho,
        issued_challenge_chirho: IssuedGd7WinnerCurrentViewChallengeChirho,
        evidence_object_digest_chirho: &str,
    ) -> Result<VerifiedGd7WinnerCurrentViewEvidenceChirho, Gd7WinnerCurrentViewRefusalChirho> {
        let challenge_chirho = issued_challenge_chirho.into_challenge_chirho();
        validate_challenge_against_group_chirho(
            &challenge_chirho,
            group_chirho,
            expected_winner_chirho,
        )?;
        let before_chirho =
            observe_expected_winner_chirho(elector_chirho, group_chirho, expected_winner_chirho)?;
        if before_chirho.term_chirho != challenge_chirho.raft_term_chirho {
            return Err(Gd7WinnerCurrentViewRefusalChirho::LeadershipChangedChirho);
        }
        if self.winner_verifier_chirho.key_id_chirho() != expected_winner_chirho.0 {
            return Err(Gd7WinnerCurrentViewRefusalChirho::WrongSignerChirho);
        }

        let evidence_chirho = load_verified_evidence_chirho(
            self.storage_chirho,
            self.winner_verifier_chirho,
            &challenge_chirho,
            evidence_object_digest_chirho,
        )?;
        let bundle_root_chirho = load_verified_bundle_root_chirho(
            self.storage_chirho,
            &evidence_chirho.evidence_chirho.view_bundle_root_chirho,
        )?;
        validate_bundle_against_evidence_chirho(
            &bundle_root_chirho,
            &evidence_chirho.evidence_chirho,
        )?;

        let after_chirho =
            observe_expected_winner_chirho(elector_chirho, group_chirho, expected_winner_chirho)?;
        if before_chirho.leader_id_chirho != after_chirho.leader_id_chirho
            || before_chirho.term_chirho != after_chirho.term_chirho
        {
            return Err(Gd7WinnerCurrentViewRefusalChirho::LeadershipChangedChirho);
        }

        Ok(VerifiedGd7WinnerCurrentViewEvidenceChirho {
            object_digest_chirho: evidence_chirho.object_digest_chirho,
            evidence_chirho: evidence_chirho.evidence_chirho,
            bundle_root_chirho,
        })
    }
}

/// Inspect one challenged response under caller-supplied election and signature trust roots.
///
/// The returned report is constructible data, not adoption authority.
pub fn inspect_challenged_gd7_winner_current_view_chirho<
    ElectorChirho: WriterElectorChirho + ?Sized,
>(
    storage_chirho: &dyn LedgerStoragePortChirho,
    winner_verifier_chirho: &dyn Gd7ReconciliationVerifierPortChirho,
    elector_chirho: &ElectorChirho,
    group_chirho: &ConsistencyGroupIdChirho,
    expected_winner_chirho: &NodeIdChirho,
    issued_challenge_chirho: IssuedGd7WinnerCurrentViewChallengeChirho,
    evidence_object_digest_chirho: &str,
) -> Result<Gd7WinnerCurrentViewInspectionChirho, Gd7WinnerCurrentViewRefusalChirho> {
    Gd7WinnerCurrentViewReaderChirho::new_chirho(storage_chirho, winner_verifier_chirho)
        .verify_challenged_chirho(
            elector_chirho,
            group_chirho,
            expected_winner_chirho,
            issued_challenge_chirho,
            evidence_object_digest_chirho,
        )
        .map(VerifiedGd7WinnerCurrentViewEvidenceChirho::into_inspection_chirho)
}

/// Seal a challenged response while retaining the exact local generation guard.
///
/// The tail provider is invoked only after guard acquisition. The resident-authority caller passes
/// its verified journal snapshot closure; tests can prove the guard remains held across the call.
pub(crate) fn seal_gd7_winner_current_view_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    signer_chirho: &dyn Gd7ReconciliationSignerPortChirho,
    local_authority_chirho: &LocalAppendAuthorityHandleChirho,
    challenge_chirho: Gd7WinnerCurrentViewChallengeChirho,
    bundle_root_chirho: &VerifiedGd7WinnerViewBundleRootChirho,
    snapshot_provider_chirho: impl FnOnce() -> Result<
        Gd7WinnerJournalSnapshotChirho,
        Gd7WinnerCurrentViewRefusalChirho,
    >,
) -> Result<VerifiedGd7WinnerCurrentViewEvidenceChirho, Gd7WinnerCurrentViewRefusalChirho> {
    let generation_guard_chirho = local_authority_chirho
        .try_acquire_chirho()
        .map_err(Gd7WinnerCurrentViewRefusalChirho::LocalAuthorityChirho)?;
    seal_gd7_winner_current_view_under_generation_chirho(
        storage_chirho,
        signer_chirho,
        local_authority_chirho.consistency_group_chirho(),
        local_authority_chirho.node_id_chirho(),
        generation_guard_chirho.published_raft_term_chirho(),
        generation_guard_chirho.process_generation_chirho(),
        challenge_chirho,
        bundle_root_chirho,
        snapshot_provider_chirho,
    )
}

/// Re-seal the exact challenge while the caller retains the handoff preparation mutex.
///
/// The concrete guard carries its consistency group and node identity, preventing a guard acquired
/// from one resident from being paired with another resident's signer or evidence.
pub(crate) fn seal_gd7_winner_current_view_during_handoff_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    signer_chirho: &dyn Gd7ReconciliationSignerPortChirho,
    preparation_chirho: &LocalAppendHandoffPreparationChirho<'_>,
    challenge_chirho: Gd7WinnerCurrentViewChallengeChirho,
    bundle_root_chirho: &VerifiedGd7WinnerViewBundleRootChirho,
    snapshot_provider_chirho: impl FnOnce() -> Result<
        Gd7WinnerJournalSnapshotChirho,
        Gd7WinnerCurrentViewRefusalChirho,
    >,
) -> Result<VerifiedGd7WinnerCurrentViewEvidenceChirho, Gd7WinnerCurrentViewRefusalChirho> {
    seal_gd7_winner_current_view_under_generation_chirho(
        storage_chirho,
        signer_chirho,
        preparation_chirho.consistency_group_chirho(),
        preparation_chirho.node_id_chirho(),
        preparation_chirho.published_raft_term_chirho(),
        preparation_chirho.process_generation_chirho(),
        challenge_chirho,
        bundle_root_chirho,
        snapshot_provider_chirho,
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "the helper binds one concrete held generation to its exact challenge and bundle"
)]
fn seal_gd7_winner_current_view_under_generation_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    signer_chirho: &dyn Gd7ReconciliationSignerPortChirho,
    consistency_group_chirho: &ConsistencyGroupIdChirho,
    local_node_chirho: &NodeIdChirho,
    published_raft_term_chirho: u64,
    process_generation_chirho: u64,
    challenge_chirho: Gd7WinnerCurrentViewChallengeChirho,
    bundle_root_chirho: &VerifiedGd7WinnerViewBundleRootChirho,
    snapshot_provider_chirho: impl FnOnce() -> Result<
        Gd7WinnerJournalSnapshotChirho,
        Gd7WinnerCurrentViewRefusalChirho,
    >,
) -> Result<VerifiedGd7WinnerCurrentViewEvidenceChirho, Gd7WinnerCurrentViewRefusalChirho> {
    validate_challenge_against_group_chirho(
        &challenge_chirho,
        consistency_group_chirho,
        local_node_chirho,
    )?;
    if signer_chirho.key_id_chirho() != local_node_chirho.0 {
        return Err(Gd7WinnerCurrentViewRefusalChirho::WrongSignerChirho);
    }
    if published_raft_term_chirho != challenge_chirho.raft_term_chirho
        || process_generation_chirho == 0
    {
        return Err(Gd7WinnerCurrentViewRefusalChirho::LeadershipChangedChirho);
    }
    let reloaded_bundle_root_chirho = load_verified_bundle_root_chirho(
        storage_chirho,
        bundle_root_chirho.object_digest_chirho(),
    )?;
    if &reloaded_bundle_root_chirho != bundle_root_chirho {
        return Err(Gd7WinnerCurrentViewRefusalChirho::BundleRootMismatchChirho);
    }
    if reloaded_bundle_root_chirho
        .root_chirho
        .consistency_group_digest_chirho
        != challenge_chirho.consistency_group_digest_chirho
    {
        return Err(Gd7WinnerCurrentViewRefusalChirho::BundleRootMismatchChirho);
    }
    let snapshot_chirho = snapshot_provider_chirho()?;
    let latest_cut_chirho = snapshot_chirho.cut_chirho;
    let genesis_digest_chirho = snapshot_chirho.genesis_digest_chirho;
    if u64::from(split_writer_epoch_chirho(latest_cut_chirho.epoch_chirho).geo_term_chirho)
        != published_raft_term_chirho
        || reloaded_bundle_root_chirho
            .root_chirho
            .winner_journal_genesis_digest_chirho
            != genesis_digest_chirho
        || reloaded_bundle_root_chirho.root_chirho.source_cut_chirho != latest_cut_chirho
    {
        return Err(Gd7WinnerCurrentViewRefusalChirho::JournalCutMismatchChirho);
    }

    let mut evidence_chirho = Gd7WinnerCurrentViewEvidenceChirho {
        schema_chirho: GD7_WINNER_CURRENT_VIEW_EVIDENCE_SCHEMA_V1_CHIRHO.to_owned(),
        challenge_digest_chirho: challenge_chirho.digest_chirho()?,
        consistency_group_digest_chirho: challenge_chirho.consistency_group_digest_chirho.clone(),
        winner_node_chirho: local_node_chirho.0.clone(),
        raft_term_chirho: published_raft_term_chirho,
        winner_process_generation_chirho: process_generation_chirho,
        winner_journal_genesis_digest_chirho: genesis_digest_chirho,
        latest_verified_journal_cut_chirho: latest_cut_chirho,
        view_bundle_root_chirho: reloaded_bundle_root_chirho.object_digest_chirho.clone(),
        key_id_chirho: signer_chirho.key_id_chirho(),
        sig_chirho: String::new(),
    };
    let unsigned_bytes_chirho = canonical_json_chirho(&evidence_chirho)?;
    let unsigned_line_chirho = std::str::from_utf8(&unsigned_bytes_chirho)
        .map_err(|_| Gd7WinnerCurrentViewRefusalChirho::SerializationChirho)?;
    evidence_chirho.sig_chirho = signer_chirho
        .sign_chirho(unsigned_line_chirho)
        .map_err(|_| Gd7WinnerCurrentViewRefusalChirho::SigningChirho)?;
    let bytes_chirho = canonical_json_chirho(&evidence_chirho)?;
    if bytes_chirho.len() > MAX_GD7_WINNER_CURRENT_VIEW_EVIDENCE_BYTES_CHIRHO {
        return Err(Gd7WinnerCurrentViewRefusalChirho::OversizedEvidenceChirho);
    }
    let object_digest_chirho = digest_bytes_chirho(&bytes_chirho);
    let path_chirho = gd7_winner_current_view_path_chirho(&object_digest_chirho)?;
    create_exact_chirho(
        storage_chirho,
        &path_chirho,
        &bytes_chirho,
        MAX_GD7_WINNER_CURRENT_VIEW_EVIDENCE_BYTES_CHIRHO,
    )?;
    let verified_chirho = load_verified_evidence_chirho(
        storage_chirho,
        signer_chirho,
        &challenge_chirho,
        &object_digest_chirho,
    )?;
    validate_bundle_against_evidence_chirho(&reloaded_bundle_root_chirho, &evidence_chirho)?;
    Ok(VerifiedGd7WinnerCurrentViewEvidenceChirho {
        object_digest_chirho: verified_chirho.object_digest_chirho,
        evidence_chirho: verified_chirho.evidence_chirho,
        bundle_root_chirho: reloaded_bundle_root_chirho,
    })
}

pub(crate) fn stage_next_gd7_winner_view_bundle_page_chirho<
    SnapshotProviderChirho,
    PageProviderChirho,
>(
    storage_chirho: &dyn LedgerStoragePortChirho,
    local_authority_chirho: &LocalAppendAuthorityHandleChirho,
    restart_chirho: Option<&Gd7WinnerViewBundleRestartChirho>,
    snapshot_provider_chirho: SnapshotProviderChirho,
    page_provider_chirho: PageProviderChirho,
) -> Result<Gd7WinnerViewBundleStageOutcomeChirho, Gd7WinnerCurrentViewRefusalChirho>
where
    SnapshotProviderChirho:
        FnOnce() -> Result<Gd7WinnerJournalSnapshotChirho, Gd7WinnerCurrentViewRefusalChirho>,
    PageProviderChirho:
        FnOnce(
            Option<&AccountIdChirho>,
        )
            -> Result<AccountNetProjectionPageSliceChirho, Gd7WinnerCurrentViewRefusalChirho>,
{
    let generation_guard_chirho = local_authority_chirho
        .try_acquire_chirho()
        .map_err(Gd7WinnerCurrentViewRefusalChirho::LocalAuthorityChirho)?;
    let group_digest_chirho =
        consistency_group_digest_chirho(local_authority_chirho.consistency_group_chirho())
            .map_err(|_| Gd7WinnerCurrentViewRefusalChirho::InvalidCoordinateChirho)?;
    bundle_chirho::stage_next_gd7_winner_view_bundle_page_guarded_chirho(
        storage_chirho,
        &group_digest_chirho,
        generation_guard_chirho.published_raft_term_chirho(),
        restart_chirho,
        snapshot_provider_chirho,
        page_provider_chirho,
    )
}

pub fn gd7_winner_current_view_path_chirho(
    object_digest_chirho: &str,
) -> Result<StoragePathChirho, Gd7WinnerCurrentViewRefusalChirho> {
    digest_sharded_path_chirho("winner-current-views-chirho", object_digest_chirho)
}

pub fn gd7_winner_view_bundle_root_path_chirho(
    object_digest_chirho: &str,
) -> Result<StoragePathChirho, Gd7WinnerCurrentViewRefusalChirho> {
    digest_sharded_path_chirho("winner-view-bundle-roots-chirho", object_digest_chirho)
}

pub(crate) fn gd7_winner_view_bundle_page_path_chirho(
    object_digest_chirho: &str,
) -> Result<StoragePathChirho, Gd7WinnerCurrentViewRefusalChirho> {
    digest_sharded_path_chirho("winner-view-bundle-pages-chirho", object_digest_chirho)
}

fn observe_expected_winner_chirho<ElectorChirho: WriterElectorChirho + ?Sized>(
    elector_chirho: &ElectorChirho,
    group_chirho: &ConsistencyGroupIdChirho,
    expected_winner_chirho: &NodeIdChirho,
) -> Result<
    cairn_writer_elector_chirho::elector_port_chirho::LeadershipChirho,
    Gd7WinnerCurrentViewRefusalChirho,
> {
    let leadership_chirho = elector_chirho.leadership_chirho(group_chirho);
    if leadership_chirho.leader_id_chirho.as_ref() != Some(expected_winner_chirho)
        || leadership_chirho.term_chirho == 0
        || leadership_chirho.term_chirho > WRITER_EPOCH_COMPONENT_MAX_CHIRHO
    {
        return Err(Gd7WinnerCurrentViewRefusalChirho::LeadershipUnavailableChirho);
    }
    Ok(leadership_chirho)
}

fn validate_challenge_against_group_chirho(
    challenge_chirho: &Gd7WinnerCurrentViewChallengeChirho,
    group_chirho: &ConsistencyGroupIdChirho,
    expected_winner_chirho: &NodeIdChirho,
) -> Result<(), Gd7WinnerCurrentViewRefusalChirho> {
    validate_challenge_chirho(challenge_chirho)?;
    let group_digest_chirho = consistency_group_digest_chirho(group_chirho)
        .map_err(|_| Gd7WinnerCurrentViewRefusalChirho::InvalidCoordinateChirho)?;
    if challenge_chirho.consistency_group_digest_chirho != group_digest_chirho
        || challenge_chirho.expected_winner_node_chirho != expected_winner_chirho.0
    {
        return Err(Gd7WinnerCurrentViewRefusalChirho::InvalidChallengeChirho);
    }
    Ok(())
}

fn validate_challenge_chirho(
    challenge_chirho: &Gd7WinnerCurrentViewChallengeChirho,
) -> Result<(), Gd7WinnerCurrentViewRefusalChirho> {
    if challenge_chirho.schema_chirho != GD7_WINNER_CURRENT_VIEW_CHALLENGE_SCHEMA_V1_CHIRHO
        || !is_lower_hex_digest_chirho(&challenge_chirho.nonce_chirho)
        || consistency_group_digest_suffix_chirho(&challenge_chirho.consistency_group_digest_chirho)
            .is_none()
        || !is_lower_hex_digest_chirho(&challenge_chirho.expected_winner_node_chirho)
        || !is_lower_hex_digest_chirho(&challenge_chirho.held_node_chirho)
        || challenge_chirho.held_node_chirho == challenge_chirho.expected_winner_node_chirho
        || !is_lower_hex_digest_chirho(&challenge_chirho.transfer_identity_digest_chirho)
        || challenge_chirho.raft_term_chirho == 0
        || challenge_chirho.raft_term_chirho > WRITER_EPOCH_COMPONENT_MAX_CHIRHO
    {
        return Err(Gd7WinnerCurrentViewRefusalChirho::InvalidChallengeChirho);
    }
    Ok(())
}

struct LoadedEvidenceChirho {
    object_digest_chirho: String,
    evidence_chirho: Gd7WinnerCurrentViewEvidenceChirho,
}

fn load_verified_evidence_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    verifier_chirho: &dyn Gd7ReconciliationVerifierPortChirho,
    challenge_chirho: &Gd7WinnerCurrentViewChallengeChirho,
    object_digest_chirho: &str,
) -> Result<LoadedEvidenceChirho, Gd7WinnerCurrentViewRefusalChirho> {
    let path_chirho = gd7_winner_current_view_path_chirho(object_digest_chirho)?;
    let bytes_chirho = read_bounded_chirho(
        storage_chirho,
        &path_chirho,
        MAX_GD7_WINNER_CURRENT_VIEW_EVIDENCE_BYTES_CHIRHO,
        Gd7WinnerCurrentViewRefusalChirho::OversizedEvidenceChirho,
    )?
    .ok_or(Gd7WinnerCurrentViewRefusalChirho::MissingEvidenceChirho)?;
    if digest_bytes_chirho(&bytes_chirho) != object_digest_chirho {
        return Err(Gd7WinnerCurrentViewRefusalChirho::ObjectDigestMismatchChirho);
    }
    let evidence_chirho: Gd7WinnerCurrentViewEvidenceChirho = parse_json_chirho(
        &bytes_chirho,
        Gd7WinnerCurrentViewRefusalChirho::MalformedEvidenceChirho,
    )?;
    validate_evidence_shape_chirho(&evidence_chirho)?;
    if canonical_json_chirho(&evidence_chirho)?.as_slice() != bytes_chirho {
        return Err(Gd7WinnerCurrentViewRefusalChirho::NonCanonicalEvidenceChirho);
    }
    if evidence_chirho.challenge_digest_chirho != challenge_chirho.digest_chirho()?
        || evidence_chirho.consistency_group_digest_chirho
            != challenge_chirho.consistency_group_digest_chirho
        || evidence_chirho.winner_node_chirho != challenge_chirho.expected_winner_node_chirho
        || evidence_chirho.raft_term_chirho != challenge_chirho.raft_term_chirho
        || evidence_chirho.key_id_chirho != verifier_chirho.key_id_chirho()
    {
        return Err(Gd7WinnerCurrentViewRefusalChirho::InvalidChallengeChirho);
    }
    let mut unsigned_chirho = evidence_chirho.clone();
    let signature_chirho = std::mem::take(&mut unsigned_chirho.sig_chirho);
    let unsigned_bytes_chirho = canonical_json_chirho(&unsigned_chirho)?;
    let unsigned_line_chirho = std::str::from_utf8(&unsigned_bytes_chirho)
        .map_err(|_| Gd7WinnerCurrentViewRefusalChirho::SerializationChirho)?;
    if !verifier_chirho.verify_chirho(unsigned_line_chirho, &signature_chirho) {
        return Err(Gd7WinnerCurrentViewRefusalChirho::InvalidSignatureChirho);
    }
    Ok(LoadedEvidenceChirho {
        object_digest_chirho: object_digest_chirho.to_owned(),
        evidence_chirho,
    })
}

fn validate_evidence_shape_chirho(
    evidence_chirho: &Gd7WinnerCurrentViewEvidenceChirho,
) -> Result<(), Gd7WinnerCurrentViewRefusalChirho> {
    if evidence_chirho.schema_chirho != GD7_WINNER_CURRENT_VIEW_EVIDENCE_SCHEMA_V1_CHIRHO
        || !is_lower_hex_digest_chirho(&evidence_chirho.challenge_digest_chirho)
        || consistency_group_digest_suffix_chirho(&evidence_chirho.consistency_group_digest_chirho)
            .is_none()
        || !is_lower_hex_digest_chirho(&evidence_chirho.winner_node_chirho)
        || evidence_chirho.key_id_chirho != evidence_chirho.winner_node_chirho
        || evidence_chirho.raft_term_chirho == 0
        || evidence_chirho.raft_term_chirho > WRITER_EPOCH_COMPONENT_MAX_CHIRHO
        || evidence_chirho.winner_process_generation_chirho == 0
        || !is_lower_hex_digest_chirho(&evidence_chirho.winner_journal_genesis_digest_chirho)
        || !is_lower_hex_digest_chirho(
            &evidence_chirho
                .latest_verified_journal_cut_chirho
                .record_digest_chirho,
        )
        || !is_lower_hex_digest_chirho(&evidence_chirho.view_bundle_root_chirho)
        || !validate_key_and_signature_chirho(
            &evidence_chirho.key_id_chirho,
            &evidence_chirho.sig_chirho,
        )
        || split_writer_epoch_chirho(
            evidence_chirho
                .latest_verified_journal_cut_chirho
                .epoch_chirho,
        )
        .geo_term_chirho as u64
            != evidence_chirho.raft_term_chirho
    {
        return Err(Gd7WinnerCurrentViewRefusalChirho::MalformedEvidenceChirho);
    }
    Ok(())
}

pub(crate) fn verify_inline_gd7_winner_current_view_inspection_chirho(
    challenge_chirho: &Gd7WinnerCurrentViewChallengeChirho,
    verifier_chirho: &dyn Gd7ReconciliationVerifierPortChirho,
    inspection_chirho: &Gd7WinnerCurrentViewInspectionChirho,
) -> Result<(), Gd7WinnerCurrentViewRefusalChirho> {
    let evidence_chirho = &inspection_chirho.evidence_chirho;
    validate_evidence_shape_chirho(evidence_chirho)?;
    if digest_bytes_chirho(&canonical_json_chirho(evidence_chirho)?)
        != inspection_chirho.evidence_object_digest_chirho
        || evidence_chirho.challenge_digest_chirho != challenge_chirho.digest_chirho()?
        || evidence_chirho.consistency_group_digest_chirho
            != challenge_chirho.consistency_group_digest_chirho
        || evidence_chirho.winner_node_chirho != challenge_chirho.expected_winner_node_chirho
        || evidence_chirho.raft_term_chirho != challenge_chirho.raft_term_chirho
        || evidence_chirho.key_id_chirho != verifier_chirho.key_id_chirho()
    {
        return Err(Gd7WinnerCurrentViewRefusalChirho::InvalidChallengeChirho);
    }
    let mut unsigned_chirho = evidence_chirho.clone();
    let signature_chirho = std::mem::take(&mut unsigned_chirho.sig_chirho);
    let unsigned_bytes_chirho = canonical_json_chirho(&unsigned_chirho)?;
    let unsigned_line_chirho = std::str::from_utf8(&unsigned_bytes_chirho)
        .map_err(|_| Gd7WinnerCurrentViewRefusalChirho::SerializationChirho)?;
    if !verifier_chirho.verify_chirho(unsigned_line_chirho, &signature_chirho) {
        return Err(Gd7WinnerCurrentViewRefusalChirho::InvalidSignatureChirho);
    }

    validate_bundle_root_shape_chirho(&inspection_chirho.bundle_root_chirho)?;
    if digest_bytes_chirho(&canonical_json_chirho(
        &inspection_chirho.bundle_root_chirho,
    )?) != inspection_chirho.bundle_root_object_digest_chirho
    {
        return Err(Gd7WinnerCurrentViewRefusalChirho::ObjectDigestMismatchChirho);
    }
    let verified_root_chirho = VerifiedGd7WinnerViewBundleRootChirho {
        object_digest_chirho: inspection_chirho.bundle_root_object_digest_chirho.clone(),
        root_chirho: inspection_chirho.bundle_root_chirho.clone(),
    };
    validate_bundle_against_evidence_chirho(&verified_root_chirho, evidence_chirho)
}

fn load_verified_bundle_root_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    object_digest_chirho: &str,
) -> Result<VerifiedGd7WinnerViewBundleRootChirho, Gd7WinnerCurrentViewRefusalChirho> {
    let path_chirho = gd7_winner_view_bundle_root_path_chirho(object_digest_chirho)?;
    let bytes_chirho = read_bounded_chirho(
        storage_chirho,
        &path_chirho,
        MAX_GD7_WINNER_VIEW_BUNDLE_ROOT_BYTES_CHIRHO,
        Gd7WinnerCurrentViewRefusalChirho::OversizedBundleRootChirho,
    )?
    .ok_or(Gd7WinnerCurrentViewRefusalChirho::MissingBundleRootChirho)?;
    if digest_bytes_chirho(&bytes_chirho) != object_digest_chirho {
        return Err(Gd7WinnerCurrentViewRefusalChirho::ObjectDigestMismatchChirho);
    }
    let root_chirho: Gd7WinnerViewBundleRootChirho = parse_json_chirho(
        &bytes_chirho,
        Gd7WinnerCurrentViewRefusalChirho::MalformedBundleRootChirho,
    )?;
    validate_bundle_root_shape_chirho(&root_chirho)?;
    if canonical_json_chirho(&root_chirho)?.as_slice() != bytes_chirho {
        return Err(Gd7WinnerCurrentViewRefusalChirho::NonCanonicalBundleRootChirho);
    }
    Ok(VerifiedGd7WinnerViewBundleRootChirho {
        object_digest_chirho: object_digest_chirho.to_owned(),
        root_chirho,
    })
}

fn validate_bundle_root_shape_chirho(
    root_chirho: &Gd7WinnerViewBundleRootChirho,
) -> Result<(), Gd7WinnerCurrentViewRefusalChirho> {
    let expected_fold_ref_chirho = account_net_projection_fold_ref_chirho().0;
    let maximum_rows_per_page_chirho =
        u64::try_from(cairn_ledger_read_model_chirho::ACCOUNT_NET_PROJECTION_PAGE_ROWS_CHIRHO)
            .map_err(|_| Gd7WinnerCurrentViewRefusalChirho::InvalidBundleRootChirho)?;
    let empty_chirho = root_chirho.page_count_chirho == 0
        && root_chirho.row_count_chirho == 0
        && root_chirho.lowest_page_ref_chirho.is_none();
    let nonempty_chirho = root_chirho.page_count_chirho > 0
        && root_chirho.row_count_chirho >= root_chirho.page_count_chirho
        && root_chirho.lowest_page_ref_chirho.is_some()
        && root_chirho.row_count_chirho
            <= root_chirho
                .page_count_chirho
                .checked_mul(maximum_rows_per_page_chirho)
                .ok_or(Gd7WinnerCurrentViewRefusalChirho::InvalidBundleRootChirho)?;
    if root_chirho.schema_chirho != GD7_WINNER_VIEW_BUNDLE_ROOT_SCHEMA_V1_CHIRHO
        || consistency_group_digest_suffix_chirho(&root_chirho.consistency_group_digest_chirho)
            .is_none()
        || root_chirho.projection_fold_ref_chirho != expected_fold_ref_chirho
        || !is_lower_hex_digest_chirho(&root_chirho.winner_journal_genesis_digest_chirho)
        || !is_lower_hex_digest_chirho(&root_chirho.source_cut_chirho.record_digest_chirho)
        || root_chirho
            .lowest_page_ref_chirho
            .as_deref()
            .is_some_and(|digest_chirho| !is_lower_hex_digest_chirho(digest_chirho))
        || (!empty_chirho && !nonempty_chirho)
    {
        return Err(Gd7WinnerCurrentViewRefusalChirho::InvalidBundleRootChirho);
    }
    Ok(())
}

fn validate_bundle_against_evidence_chirho(
    bundle_root_chirho: &VerifiedGd7WinnerViewBundleRootChirho,
    evidence_chirho: &Gd7WinnerCurrentViewEvidenceChirho,
) -> Result<(), Gd7WinnerCurrentViewRefusalChirho> {
    if bundle_root_chirho.object_digest_chirho != evidence_chirho.view_bundle_root_chirho
        || bundle_root_chirho
            .root_chirho
            .consistency_group_digest_chirho
            != evidence_chirho.consistency_group_digest_chirho
        || bundle_root_chirho
            .root_chirho
            .winner_journal_genesis_digest_chirho
            != evidence_chirho.winner_journal_genesis_digest_chirho
        || bundle_root_chirho.root_chirho.source_cut_chirho
            != evidence_chirho.latest_verified_journal_cut_chirho
    {
        return Err(Gd7WinnerCurrentViewRefusalChirho::BundleRootMismatchChirho);
    }
    Ok(())
}

fn digest_sharded_path_chirho(
    family_chirho: &str,
    object_digest_chirho: &str,
) -> Result<StoragePathChirho, Gd7WinnerCurrentViewRefusalChirho> {
    if !is_lower_hex_digest_chirho(object_digest_chirho) {
        return Err(Gd7WinnerCurrentViewRefusalChirho::InvalidCoordinateChirho);
    }
    Ok(StoragePathChirho::new_chirho(format!(
        "{GD7_RECONCILIATION_NAMESPACE_CHIRHO}/{family_chirho}/{}/{}/{object_digest_chirho}.json",
        &object_digest_chirho[..2],
        &object_digest_chirho[2..4],
    )))
}

fn create_exact_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    path_chirho: &StoragePathChirho,
    bytes_chirho: &[u8],
    maximum_chirho: usize,
) -> Result<(), Gd7WinnerCurrentViewRefusalChirho> {
    match storage_chirho
        .create_durable_chirho(path_chirho, bytes_chirho)
        .map_err(|_| Gd7WinnerCurrentViewRefusalChirho::StorageChirho)?
    {
        CreateDurableOutcomeChirho::CreatedChirho => Ok(()),
        CreateDurableOutcomeChirho::AlreadyExistsChirho => {
            let existing_chirho = read_bounded_chirho(
                storage_chirho,
                path_chirho,
                maximum_chirho,
                Gd7WinnerCurrentViewRefusalChirho::ImmutableCollisionChirho,
            )?
            .ok_or(Gd7WinnerCurrentViewRefusalChirho::ImmutableCollisionChirho)?;
            if existing_chirho == bytes_chirho {
                Ok(())
            } else {
                Err(Gd7WinnerCurrentViewRefusalChirho::ImmutableCollisionChirho)
            }
        }
    }
}

fn read_bounded_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    path_chirho: &StoragePathChirho,
    maximum_chirho: usize,
    oversized_chirho: Gd7WinnerCurrentViewRefusalChirho,
) -> Result<Option<Vec<u8>>, Gd7WinnerCurrentViewRefusalChirho> {
    let Some(len_chirho) = storage_chirho
        .object_len_chirho(path_chirho)
        .map_err(|_| Gd7WinnerCurrentViewRefusalChirho::StorageChirho)?
    else {
        return Ok(None);
    };
    if len_chirho > maximum_chirho as u64 {
        return Err(oversized_chirho);
    }
    let bytes_chirho = if len_chirho == 0 {
        Vec::new()
    } else {
        storage_chirho
            .read_exact_range_chirho(path_chirho, 0, len_chirho)
            .map_err(|_| Gd7WinnerCurrentViewRefusalChirho::StorageChirho)?
    };
    let stable_len_chirho = storage_chirho
        .object_len_chirho(path_chirho)
        .map_err(|_| Gd7WinnerCurrentViewRefusalChirho::StorageChirho)?;
    if bytes_chirho.len() != len_chirho as usize || stable_len_chirho != Some(len_chirho) {
        return Err(Gd7WinnerCurrentViewRefusalChirho::StorageChirho);
    }
    Ok(Some(bytes_chirho))
}

fn parse_json_chirho<ValueChirho: DeserializeOwned>(
    bytes_chirho: &[u8],
    malformed_chirho: Gd7WinnerCurrentViewRefusalChirho,
) -> Result<ValueChirho, Gd7WinnerCurrentViewRefusalChirho> {
    serde_json::from_slice(bytes_chirho).map_err(|_| malformed_chirho)
}

fn canonical_json_chirho(
    value_chirho: &impl Serialize,
) -> Result<Vec<u8>, Gd7WinnerCurrentViewRefusalChirho> {
    serde_json::to_vec(value_chirho)
        .map_err(|_| Gd7WinnerCurrentViewRefusalChirho::SerializationChirho)
}

fn digest_bytes_chirho(bytes_chirho: &[u8]) -> String {
    blake3::hash(bytes_chirho).to_hex().to_string()
}

fn lower_hex_chirho(bytes_chirho: &[u8]) -> String {
    const HEX_CHIRHO: &[u8; 16] = b"0123456789abcdef";
    let mut output_chirho = String::with_capacity(bytes_chirho.len() * 2);
    for byte_chirho in bytes_chirho {
        output_chirho.push(HEX_CHIRHO[(byte_chirho >> 4) as usize] as char);
        output_chirho.push(HEX_CHIRHO[(byte_chirho & 0x0f) as usize] as char);
    }
    output_chirho
}

#[cfg(test)]
#[path = "current_view_chirho/current_view_tests_chirho.rs"]
mod current_view_tests_chirho;

#[cfg(test)]
#[path = "current_view_chirho/bundle_tests_chirho.rs"]
mod bundle_tests_chirho;

#[cfg(test)]
#[path = "current_view_chirho/fork_baseline_tests_chirho.rs"]
mod fork_baseline_tests_chirho;

#[cfg(test)]
#[path = "current_view_chirho/held_transfer_tests_chirho.rs"]
mod held_transfer_tests_chirho;

#[cfg(test)]
#[path = "current_view_chirho/adoption_tests_chirho.rs"]
mod adoption_tests_chirho;

#[cfg(test)]
#[path = "current_view_chirho/winner_handoff_tests_chirho.rs"]
mod winner_handoff_tests_chirho;

#[cfg(test)]
#[path = "current_view_chirho/winner_history_tests_chirho.rs"]
mod winner_history_tests_chirho;
