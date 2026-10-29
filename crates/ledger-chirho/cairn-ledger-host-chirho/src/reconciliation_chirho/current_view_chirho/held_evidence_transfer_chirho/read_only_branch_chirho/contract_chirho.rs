// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::super::super::winner_history_chirho::Gd7WinnerHistoryRefusalChirho;
use super::super::{Gd7AccountNetCompositionRefusalChirho, Gd7HeldEvidenceTransferIdentityChirho};
use cairn_ledger_log_chirho::losing_suffix_chirho::{
    LosingSuffixReadErrorChirho, MAX_LOSING_SUFFIX_PAGE_BYTES_CHIRHO,
};
use cairn_ledger_model_chirho::record_chirho::LedgerRecordChirho;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt;

pub(super) const GD7_READ_ONLY_BRANCH_PREFIX_PAGE_SCHEMA_V1_CHIRHO: &str =
    "gd7-read-only-branch-prefix-page-v1-chirho";
pub const GD7_READ_ONLY_BRANCH_PREFIX_ROOT_SCHEMA_V1_CHIRHO: &str =
    "gd7-read-only-branch-prefix-root-v1-chirho";
pub const GD7_READ_ONLY_BRANCH_CHECKPOINT_SCHEMA_V1_CHIRHO: &str =
    "gd7-read-only-branch-checkpoint-v1-chirho";
pub const GD7_READ_ONLY_BRANCH_HEAD_SCHEMA_V1_CHIRHO: &str = "gd7-read-only-branch-head-v1-chirho";
pub const MAX_GD7_READ_ONLY_BRANCH_PREFIX_PAGE_BYTES_CHIRHO: usize =
    MAX_LOSING_SUFFIX_PAGE_BYTES_CHIRHO + 1024 * 1024;
pub const MAX_GD7_READ_ONLY_BRANCH_PREFIX_ROOT_BYTES_CHIRHO: usize = 32 * 1024;
pub const MAX_GD7_READ_ONLY_BRANCH_CHECKPOINT_BYTES_CHIRHO: usize = 64 * 1024;
pub const MAX_GD7_READ_ONLY_BRANCH_HEAD_BYTES_CHIRHO: usize = 8 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Gd7ReadOnlyBranchPrefixRecordChirho {
    pub(super) record_digest_chirho: String,
    pub(super) record_chirho: LedgerRecordChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Gd7ReadOnlyBranchPrefixPageChirho {
    pub(super) schema_chirho: String,
    pub(super) transfer_identity_digest_chirho: String,
    pub(super) page_index_chirho: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) newer_page_ref_chirho: Option<String>,
    pub(super) records_newest_first_chirho: Vec<Gd7ReadOnlyBranchPrefixRecordChirho>,
    pub(super) cumulative_record_count_chirho: u64,
}

/// Held-signed completion root for the losing journal's exact canonical prefix through the fork.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gd7ReadOnlyBranchPrefixRootChirho {
    pub schema_chirho: String,
    pub transfer_identity_chirho: Gd7HeldEvidenceTransferIdentityChirho,
    pub transfer_identity_digest_chirho: String,
    pub genesis_line_chirho: String,
    pub losing_tail_epoch_chirho: u64,
    pub losing_tail_seq_chirho: u64,
    pub losing_tail_record_digest_chirho: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oldest_page_ref_chirho: Option<String>,
    pub page_count_chirho: u64,
    pub record_count_chirho: u64,
    pub key_id_chirho: String,
    pub sig_chirho: String,
}

/// Held-signed immutable candidate binding the prefix, accepted winner suffix, and exact view proof.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gd7ReadOnlyBranchCheckpointChirho {
    pub schema_chirho: String,
    pub transfer_identity_chirho: Gd7HeldEvidenceTransferIdentityChirho,
    pub transfer_identity_digest_chirho: String,
    pub evidence_checkpoint_ref_chirho: String,
    pub held_view_checkpoint_ref_chirho: String,
    pub held_view_bundle_root_ref_chirho: String,
    pub fork_baseline_root_ref_chirho: String,
    pub prefix_root_ref_chirho: String,
    pub winner_history_root_ref_chirho: String,
    pub prefix_record_count_chirho: u64,
    pub winner_suffix_record_count_chirho: u64,
    pub canonical_record_count_chirho: u64,
    pub account_net_row_count_chirho: u64,
    pub key_id_chirho: String,
    pub sig_chirho: String,
}

/// Mutable held-local pointer to one exact immutable read-only branch candidate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gd7ReadOnlyBranchHeadChirho {
    pub schema_chirho: String,
    pub transfer_identity_digest_chirho: String,
    pub active_checkpoint_ref_chirho: String,
    pub key_id_chirho: String,
    pub sig_chirho: String,
}

/// Opaque prepared candidate. Its immutable objects exist, but no installed head names them yet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedGd7ReadOnlyBranchChirho {
    pub(super) checkpoint_ref_chirho: String,
    pub(super) checkpoint_chirho: Gd7ReadOnlyBranchCheckpointChirho,
}

impl PreparedGd7ReadOnlyBranchChirho {
    pub fn checkpoint_ref_chirho(&self) -> &str {
        &self.checkpoint_ref_chirho
    }
}

/// One installed head and its held-signed immutable checkpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActiveGd7ReadOnlyBranchChirho {
    pub checkpoint_ref_chirho: String,
    pub checkpoint_chirho: Gd7ReadOnlyBranchCheckpointChirho,
}

/// Opaque proof that the installed head, both history halves, their junction, and view evidence
/// were reverified at one stable held-evidence cut.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedGd7ReadOnlyBranchChirho {
    pub(super) checkpoint_ref_chirho: String,
    pub(super) prefix_root_ref_chirho: String,
    pub(super) winner_history_root_ref_chirho: String,
    pub(super) canonical_record_count_chirho: u64,
}

impl VerifiedGd7ReadOnlyBranchChirho {
    pub fn checkpoint_ref_chirho(&self) -> &str {
        &self.checkpoint_ref_chirho
    }

    pub fn prefix_root_ref_chirho(&self) -> &str {
        &self.prefix_root_ref_chirho
    }

    pub fn winner_history_root_ref_chirho(&self) -> &str {
        &self.winner_history_root_ref_chirho
    }

    pub fn canonical_record_count_chirho(&self) -> u64 {
        self.canonical_record_count_chirho
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants must carry the Chirho suffix"
)]
pub enum Gd7ReadOnlyBranchRefusalChirho {
    AccountNetChirho(Gd7AccountNetCompositionRefusalChirho),
    LosingSuffixChirho(LosingSuffixReadErrorChirho),
    WinnerHistoryChirho(Gd7WinnerHistoryRefusalChirho),
    InvalidIdentityChirho,
    WrongHeldSignerChirho,
    InvalidLosingTailChirho,
    InvalidPrefixShapeChirho,
    InvalidPrefixChainChirho,
    InvalidWinnerJunctionChirho,
    InvalidCheckpointChirho,
    StaleEvidenceChirho,
    MissingObjectChirho,
    MalformedObjectChirho,
    NonCanonicalObjectChirho,
    OversizedObjectChirho,
    ObjectDigestMismatchChirho,
    ImmutableCollisionChirho,
    InvalidSignatureChirho,
    SerializationChirho,
    SigningChirho,
    StorageChirho,
    ArithmeticOverflowChirho,
}

impl fmt::Display for Gd7ReadOnlyBranchRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AccountNetChirho(error_chirho) => {
                write!(
                    formatter_chirho,
                    "GD7 account-net proof refused: {error_chirho}"
                )
            }
            Self::LosingSuffixChirho(_) => {
                formatter_chirho.write_str("GD7 losing prefix page verification failed")
            }
            Self::WinnerHistoryChirho(error_chirho) => {
                write!(
                    formatter_chirho,
                    "GD7 winner suffix refused: {error_chirho}"
                )
            }
            Self::InvalidIdentityChirho => {
                formatter_chirho.write_str("GD7 read-only branch identity is invalid")
            }
            Self::WrongHeldSignerChirho => {
                formatter_chirho.write_str("GD7 read-only branch used the wrong held signer")
            }
            Self::InvalidLosingTailChirho => {
                formatter_chirho.write_str("GD7 read-only branch losing tail differs")
            }
            Self::InvalidPrefixShapeChirho => {
                formatter_chirho.write_str("GD7 read-only branch prefix shape is invalid")
            }
            Self::InvalidPrefixChainChirho => {
                formatter_chirho.write_str("GD7 read-only branch prefix chain is invalid")
            }
            Self::InvalidWinnerJunctionChirho => {
                formatter_chirho.write_str("GD7 read-only branch winner junction is invalid")
            }
            Self::InvalidCheckpointChirho => {
                formatter_chirho.write_str("GD7 read-only branch checkpoint is invalid")
            }
            Self::StaleEvidenceChirho => {
                formatter_chirho.write_str("GD7 read-only branch evidence changed")
            }
            Self::MissingObjectChirho => {
                formatter_chirho.write_str("GD7 read-only branch object is missing")
            }
            Self::MalformedObjectChirho => {
                formatter_chirho.write_str("GD7 read-only branch object is malformed")
            }
            Self::NonCanonicalObjectChirho => {
                formatter_chirho.write_str("GD7 read-only branch object is non-canonical")
            }
            Self::OversizedObjectChirho => {
                formatter_chirho.write_str("GD7 read-only branch object is oversized")
            }
            Self::ObjectDigestMismatchChirho => {
                formatter_chirho.write_str("GD7 read-only branch object digest differs")
            }
            Self::ImmutableCollisionChirho => {
                formatter_chirho.write_str("GD7 read-only branch immutable object collided")
            }
            Self::InvalidSignatureChirho => {
                formatter_chirho.write_str("GD7 read-only branch signature is invalid")
            }
            Self::SerializationChirho => {
                formatter_chirho.write_str("GD7 read-only branch serialization failed")
            }
            Self::SigningChirho => {
                formatter_chirho.write_str("GD7 read-only branch signing failed")
            }
            Self::StorageChirho => {
                formatter_chirho.write_str("GD7 read-only branch storage failed")
            }
            Self::ArithmeticOverflowChirho => {
                formatter_chirho.write_str("GD7 read-only branch arithmetic refused")
            }
        }
    }
}

impl Error for Gd7ReadOnlyBranchRefusalChirho {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::AccountNetChirho(error_chirho) => Some(error_chirho),
            Self::WinnerHistoryChirho(error_chirho) => Some(error_chirho),
            _ => None,
        }
    }
}

impl From<Gd7AccountNetCompositionRefusalChirho> for Gd7ReadOnlyBranchRefusalChirho {
    fn from(error_chirho: Gd7AccountNetCompositionRefusalChirho) -> Self {
        Self::AccountNetChirho(error_chirho)
    }
}

impl From<LosingSuffixReadErrorChirho> for Gd7ReadOnlyBranchRefusalChirho {
    fn from(error_chirho: LosingSuffixReadErrorChirho) -> Self {
        Self::LosingSuffixChirho(error_chirho)
    }
}

impl From<Gd7WinnerHistoryRefusalChirho> for Gd7ReadOnlyBranchRefusalChirho {
    fn from(error_chirho: Gd7WinnerHistoryRefusalChirho) -> Self {
        Self::WinnerHistoryChirho(error_chirho)
    }
}
