// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Bounded canonical winner-journal evidence for one accepted GD7 handoff.
//!
//! Workflow:
//! `spec-chirho/workflows-chirho/distributed-ha-chirho/cf8-gd7-deposed-fork-reconciliation-design-chirho.md`.
//! This module persists and verifies evidence only. It cannot adopt a history, move a served ref,
//! authorize compensation, release a winner handoff, converge a held node, or enable writes.
//! The configured journal root authenticates every ordinary ledger record; the winner control key
//! separately authenticates the completion root and therefore the selected-winner identity.

use super::{
    is_lower_hex_digest_chirho, validate_identity_chirho, validate_key_and_signature_chirho,
};
use crate::reconciliation_chirho::{
    gd7_reconciliation_identity_digest_chirho, Gd7ForkCoordinateChirho,
    Gd7LedgerRecordVerifierPortChirho, Gd7ReconciliationIdentityChirho,
    Gd7ReconciliationSignerPortChirho, Gd7ReconciliationVerifierPortChirho,
};
use cairn_ledger_log_chirho::losing_suffix_chirho::{
    LosingSuffixCoordinateChirho, LosingSuffixJournalIdentityChirho, LosingSuffixPageRequestChirho,
    LosingSuffixReadErrorChirho, LosingSuffixReaderChirho, VerifiedLosingSuffixPageChirho,
    MAX_LOSING_SUFFIX_CURSOR_BYTES_CHIRHO, MAX_LOSING_SUFFIX_PAGE_BYTES_CHIRHO,
    MAX_LOSING_SUFFIX_PAGE_RECORDS_CHIRHO,
};
use cairn_ledger_log_chirho::ports_chirho::{
    CreateDurableOutcomeChirho, LedgerStoragePortChirho, StoragePathChirho,
};
use cairn_ledger_model_chirho::ids_chirho::DigestChirho;
use cairn_ledger_model_chirho::record_chirho::LedgerRecordChirho;
use cairn_ledger_model_chirho::wire_chirho::{
    canonical_ledger_record_line_chirho, ledger_record_signed_content_line_chirho,
    stored_line_digest_chirho,
};
use cairn_writer_head_chirho::writer_head_chirho::split_writer_epoch_chirho;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::error::Error;
use std::fmt;

const GD7_RECONCILIATION_NAMESPACE_CHIRHO: &str = "gd7-reconciliation-chirho";
const GD7_WINNER_HISTORY_PAGE_SCHEMA_V1_CHIRHO: &str = "gd7-winner-history-page-v1-chirho";
pub const GD7_WINNER_HISTORY_ROOT_SCHEMA_V1_CHIRHO: &str = "gd7-winner-history-root-v1-chirho";
pub const MAX_GD7_WINNER_HISTORY_PAGE_BYTES_CHIRHO: usize =
    MAX_LOSING_SUFFIX_PAGE_BYTES_CHIRHO + 1024 * 1024;
pub const MAX_GD7_WINNER_HISTORY_ROOT_BYTES_CHIRHO: usize = 16 * 1024;

/// Exact evidence coordinate shared by every winner-history page and its signed root.
///
/// The fork coordinate is not caller-selected evidence. The retained reconciliation identity was
/// already bound to the `CrossZoneAnchorChirho` on the winner's verified first higher-term record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gd7WinnerHistoryIdentityChirho {
    pub reconciliation_identity_chirho: Gd7ReconciliationIdentityChirho,
    pub reconciliation_identity_digest_chirho: String,
    pub winner_handoff_attempt_digest_chirho: String,
}

impl Gd7WinnerHistoryIdentityChirho {
    pub fn new_chirho(
        reconciliation_identity_chirho: Gd7ReconciliationIdentityChirho,
        winner_handoff_attempt_digest_chirho: String,
    ) -> Result<Self, Gd7WinnerHistoryRefusalChirho> {
        if !validate_identity_chirho(&reconciliation_identity_chirho)
            || !is_lower_hex_digest_chirho(&winner_handoff_attempt_digest_chirho)
        {
            return Err(Gd7WinnerHistoryRefusalChirho::InvalidIdentityChirho);
        }
        let reconciliation_identity_digest_chirho =
            gd7_reconciliation_identity_digest_chirho(&reconciliation_identity_chirho)
                .map_err(|_| Gd7WinnerHistoryRefusalChirho::InvalidIdentityChirho)?;
        Ok(Self {
            reconciliation_identity_chirho,
            reconciliation_identity_digest_chirho,
            winner_handoff_attempt_digest_chirho,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Gd7WinnerHistoryRecordChirho {
    record_digest_chirho: String,
    record_chirho: LedgerRecordChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Gd7WinnerHistoryPageChirho {
    schema_chirho: String,
    identity_chirho: Gd7WinnerHistoryIdentityChirho,
    page_index_chirho: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    newer_page_ref_chirho: Option<String>,
    records_newest_first_chirho: Vec<Gd7WinnerHistoryRecordChirho>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    next_cursor_object_ref_chirho: Option<String>,
    reached_fork_anchor_chirho: bool,
    cumulative_record_count_chirho: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct VerifiedGd7WinnerHistoryPageChirho {
    object_digest_chirho: String,
    page_chirho: Gd7WinnerHistoryPageChirho,
}

pub(super) struct Gd7WinnerHistoryTransferPageChirho {
    pub canonical_bytes_chirho: Vec<u8>,
    pub page_index_chirho: u64,
    pub next_page_ref_chirho: Option<String>,
}

/// Winner-control-root-signed completion of one exact canonical suffix chain.
///
/// The root authenticates page-chain completion under the accepted handoff identity. Individual
/// ledger records remain independently verified under the winner journal root when a held node
/// consumes the complete chain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gd7WinnerHistoryRootChirho {
    pub schema_chirho: String,
    pub identity_chirho: Gd7WinnerHistoryIdentityChirho,
    pub oldest_page_ref_chirho: String,
    pub page_count_chirho: u64,
    pub record_count_chirho: u64,
    pub key_id_chirho: String,
    pub sig_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedGd7WinnerHistoryRootChirho {
    object_digest_chirho: String,
    root_chirho: Gd7WinnerHistoryRootChirho,
}

impl VerifiedGd7WinnerHistoryRootChirho {
    pub fn object_digest_chirho(&self) -> &str {
        &self.object_digest_chirho
    }

    pub fn root_chirho(&self) -> &Gd7WinnerHistoryRootChirho {
        &self.root_chirho
    }
}

/// Opaque proof that the complete signed root and every ledger record were reverified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedGd7WinnerHistoryChainChirho {
    root_chirho: VerifiedGd7WinnerHistoryRootChirho,
}

impl VerifiedGd7WinnerHistoryChainChirho {
    pub fn root_chirho(&self) -> &VerifiedGd7WinnerHistoryRootChirho {
        &self.root_chirho
    }
}

/// Opaque in-process continuation. Losing it safely restarts from the winner tail.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Gd7WinnerHistoryRestartChirho {
    page_ref_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants must carry the Chirho suffix"
)]
pub enum Gd7WinnerHistoryStageOutcomeChirho {
    ContinueChirho {
        restart_chirho: Gd7WinnerHistoryRestartChirho,
    },
    CompleteChirho {
        root_chirho: Box<VerifiedGd7WinnerHistoryRootChirho>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants must carry the Chirho suffix"
)]
pub enum Gd7WinnerHistoryRefusalChirho {
    InvalidIdentityChirho,
    InvalidReferenceChirho,
    InvalidPageShapeChirho,
    InvalidRootShapeChirho,
    MalformedPageChirho,
    MalformedRootChirho,
    NonCanonicalPageChirho,
    NonCanonicalRootChirho,
    OversizedPageChirho,
    OversizedRootChirho,
    MissingObjectChirho,
    ObjectDigestMismatchChirho,
    ImmutableCollisionChirho,
    RecordEncodingChirho,
    RecordChainMismatchChirho,
    InvalidLedgerSignatureChirho,
    InvalidRootSignatureChirho,
    WrongControlSignerChirho,
    WrongJournalLabelChirho,
    IncompleteChainChirho,
    ArithmeticOverflowChirho,
    SigningChirho,
    LosingSuffixChirho(LosingSuffixReadErrorChirho),
    StorageChirho,
}

impl fmt::Display for Gd7WinnerHistoryRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter_chirho.write_str(match self {
            Self::InvalidIdentityChirho => "GD7 winner-history identity is invalid",
            Self::InvalidReferenceChirho => "GD7 winner-history reference is invalid",
            Self::InvalidPageShapeChirho => "GD7 winner-history page shape is invalid",
            Self::InvalidRootShapeChirho => "GD7 winner-history root shape is invalid",
            Self::MalformedPageChirho => "GD7 winner-history page is malformed",
            Self::MalformedRootChirho => "GD7 winner-history root is malformed",
            Self::NonCanonicalPageChirho => "GD7 winner-history page is not canonical",
            Self::NonCanonicalRootChirho => "GD7 winner-history root is not canonical",
            Self::OversizedPageChirho => "GD7 winner-history page exceeds its fixed bound",
            Self::OversizedRootChirho => "GD7 winner-history root exceeds its fixed bound",
            Self::MissingObjectChirho => "GD7 winner-history object is missing",
            Self::ObjectDigestMismatchChirho => {
                "GD7 winner-history object digest mismatches its address"
            }
            Self::ImmutableCollisionChirho => "GD7 winner-history immutable object collided",
            Self::RecordEncodingChirho => "GD7 winner-history record encoding is invalid",
            Self::RecordChainMismatchChirho => "GD7 winner-history record chain mismatches",
            Self::InvalidLedgerSignatureChirho => "GD7 winner-history ledger signature is invalid",
            Self::InvalidRootSignatureChirho => "GD7 winner-history root signature is invalid",
            Self::WrongControlSignerChirho => {
                "GD7 winner-history control signer is not the selected winner"
            }
            Self::WrongJournalLabelChirho => {
                "GD7 winner-history record label mismatches the injected journal verifier"
            }
            Self::IncompleteChainChirho => "GD7 winner-history page chain is incomplete",
            Self::ArithmeticOverflowChirho => "GD7 winner-history counter overflowed",
            Self::SigningChirho => "GD7 winner-history root signing failed",
            Self::LosingSuffixChirho(_) => "GD7 winner-history bounded suffix read failed",
            Self::StorageChirho => "GD7 winner-history storage operation failed",
        })
    }
}

impl Error for Gd7WinnerHistoryRefusalChirho {}

impl From<LosingSuffixReadErrorChirho> for Gd7WinnerHistoryRefusalChirho {
    fn from(error_chirho: LosingSuffixReadErrorChirho) -> Self {
        Self::LosingSuffixChirho(error_chirho)
    }
}

pub fn gd7_winner_history_page_path_chirho(
    object_digest_chirho: &str,
) -> Result<StoragePathChirho, Gd7WinnerHistoryRefusalChirho> {
    content_addressed_path_chirho("winner-history-pages-chirho", object_digest_chirho, "json")
}

pub fn gd7_winner_history_cursor_path_chirho(
    object_digest_chirho: &str,
) -> Result<StoragePathChirho, Gd7WinnerHistoryRefusalChirho> {
    content_addressed_path_chirho("winner-history-cursors-chirho", object_digest_chirho, "bin")
}

pub fn gd7_winner_history_root_path_chirho(
    object_digest_chirho: &str,
) -> Result<StoragePathChirho, Gd7WinnerHistoryRefusalChirho> {
    content_addressed_path_chirho("winner-history-roots-chirho", object_digest_chirho, "json")
}

/// Stage at most one authenticated winner-suffix page.
///
/// This function does not mint or retain the winner handoff. Its production caller must hold the
/// exact accepted handoff while invoking the reader and while signing a completed root. The
/// ledger-log reader mints an opaque page only after verifying every record signature against its
/// injected journal root. This layer additionally preserves label hygiene by requiring each record
/// label to match that injected journal label; the label never selects trust. A completed root is
/// not a substitute for the separate complete-chain verifier that a held consumer must run.
pub(super) fn stage_next_gd7_winner_history_page_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    control_signer_chirho: &dyn Gd7ReconciliationSignerPortChirho,
    winner_journal_chirho: &dyn LosingSuffixReaderChirho,
    identity_chirho: &Gd7WinnerHistoryIdentityChirho,
    restart_chirho: Option<&Gd7WinnerHistoryRestartChirho>,
) -> Result<Gd7WinnerHistoryStageOutcomeChirho, Gd7WinnerHistoryRefusalChirho> {
    validate_history_identity_chirho(identity_chirho)?;
    let newer_page_chirho = restart_chirho
        .map(|restart_chirho| {
            load_verified_history_page_chirho(
                storage_chirho,
                &restart_chirho.page_ref_chirho,
                identity_chirho,
            )
        })
        .transpose()?;
    if let Some(newer_page_chirho) = &newer_page_chirho {
        if newer_page_chirho.page_chirho.reached_fork_anchor_chirho {
            return persist_history_root_chirho(
                storage_chirho,
                control_signer_chirho,
                identity_chirho,
                newer_page_chirho,
            )
            .map(
                |root_chirho| Gd7WinnerHistoryStageOutcomeChirho::CompleteChirho {
                    root_chirho: Box::new(root_chirho),
                },
            );
        }
    }

    let reconciliation_chirho = &identity_chirho.reconciliation_identity_chirho;
    let mut request_chirho = LosingSuffixPageRequestChirho::new_chirho(
        LosingSuffixJournalIdentityChirho::new_chirho(DigestChirho(
            reconciliation_chirho
                .winner_journal_genesis_digest_chirho
                .clone(),
        )),
        LosingSuffixCoordinateChirho::new_chirho(
            reconciliation_chirho.winner_journal_tail_chirho.seq_chirho,
            DigestChirho(
                reconciliation_chirho
                    .winner_journal_tail_chirho
                    .record_digest_chirho
                    .clone(),
            ),
        ),
        LosingSuffixCoordinateChirho::new_chirho(
            reconciliation_chirho.fork_chirho.seq_chirho,
            DigestChirho(
                reconciliation_chirho
                    .fork_chirho
                    .record_digest_chirho
                    .clone(),
            ),
        ),
        MAX_LOSING_SUFFIX_PAGE_RECORDS_CHIRHO,
        MAX_LOSING_SUFFIX_PAGE_BYTES_CHIRHO,
    );
    if let Some(cursor_ref_chirho) = newer_page_chirho.as_ref().and_then(|page_chirho| {
        page_chirho
            .page_chirho
            .next_cursor_object_ref_chirho
            .as_deref()
    }) {
        let cursor_path_chirho = gd7_winner_history_cursor_path_chirho(cursor_ref_chirho)?;
        let cursor_bytes_chirho = read_bounded_object_chirho(
            storage_chirho,
            &cursor_path_chirho,
            MAX_LOSING_SUFFIX_CURSOR_BYTES_CHIRHO,
            Gd7WinnerHistoryRefusalChirho::OversizedPageChirho,
        )?;
        if digest_bytes_chirho(&cursor_bytes_chirho) != cursor_ref_chirho {
            return Err(Gd7WinnerHistoryRefusalChirho::ObjectDigestMismatchChirho);
        }
        request_chirho = request_chirho.with_cursor_chirho(
            winner_journal_chirho
                .decode_verified_losing_suffix_cursor_chirho(&cursor_bytes_chirho)?,
        );
    }
    let suffix_page_chirho =
        winner_journal_chirho.read_verified_losing_suffix_page_chirho(&request_chirho)?;
    let next_cursor_object_ref_chirho =
        persist_next_cursor_chirho(storage_chirho, &suffix_page_chirho)?;
    let page_chirho = build_history_page_chirho(
        identity_chirho,
        newer_page_chirho.as_ref(),
        &suffix_page_chirho,
        &winner_journal_chirho.injected_journal_key_id_chirho(),
        next_cursor_object_ref_chirho,
    )?;
    let verified_page_chirho =
        persist_history_page_chirho(storage_chirho, page_chirho, identity_chirho)?;
    if !verified_page_chirho.page_chirho.reached_fork_anchor_chirho {
        return Ok(Gd7WinnerHistoryStageOutcomeChirho::ContinueChirho {
            restart_chirho: Gd7WinnerHistoryRestartChirho {
                page_ref_chirho: verified_page_chirho.object_digest_chirho,
            },
        });
    }
    persist_history_root_chirho(
        storage_chirho,
        control_signer_chirho,
        identity_chirho,
        &verified_page_chirho,
    )
    .map(
        |root_chirho| Gd7WinnerHistoryStageOutcomeChirho::CompleteChirho {
            root_chirho: Box::new(root_chirho),
        },
    )
}

pub fn load_verified_gd7_winner_history_root_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    object_digest_chirho: &str,
    expected_identity_chirho: &Gd7WinnerHistoryIdentityChirho,
    control_verifier_chirho: &dyn Gd7ReconciliationVerifierPortChirho,
) -> Result<VerifiedGd7WinnerHistoryRootChirho, Gd7WinnerHistoryRefusalChirho> {
    if !is_lower_hex_digest_chirho(object_digest_chirho) {
        return Err(Gd7WinnerHistoryRefusalChirho::InvalidReferenceChirho);
    }
    let path_chirho = gd7_winner_history_root_path_chirho(object_digest_chirho)?;
    let bytes_chirho = read_bounded_object_chirho(
        storage_chirho,
        &path_chirho,
        MAX_GD7_WINNER_HISTORY_ROOT_BYTES_CHIRHO,
        Gd7WinnerHistoryRefusalChirho::OversizedRootChirho,
    )?;
    if digest_bytes_chirho(&bytes_chirho) != object_digest_chirho {
        return Err(Gd7WinnerHistoryRefusalChirho::ObjectDigestMismatchChirho);
    }
    verify_root_bytes_chirho(
        &bytes_chirho,
        object_digest_chirho,
        expected_identity_chirho,
        control_verifier_chirho,
    )
}

/// Reverify one complete winner-history root and every canonical ledger record it reaches.
pub fn verify_complete_gd7_winner_history_chain_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    root_object_digest_chirho: &str,
    expected_identity_chirho: &Gd7WinnerHistoryIdentityChirho,
    control_verifier_chirho: &dyn Gd7ReconciliationVerifierPortChirho,
    ledger_verifier_chirho: &dyn Gd7LedgerRecordVerifierPortChirho,
) -> Result<VerifiedGd7WinnerHistoryChainChirho, Gd7WinnerHistoryRefusalChirho> {
    verify_complete_gd7_winner_history_chain_with_records_chirho(
        storage_chirho,
        root_object_digest_chirho,
        expected_identity_chirho,
        control_verifier_chirho,
        ledger_verifier_chirho,
        |_record_chirho| {},
    )
}

/// Reverify the complete chain and visit its records in canonical oldest-to-newest order.
///
/// This is crate-internal evidence plumbing for GD7 composition. The visitor receives no storage
/// or mutation authority, and the full chain remains verified even if the visitor records a local
/// composition refusal.
pub(super) fn verify_complete_gd7_winner_history_chain_with_records_chirho<VisitChirho>(
    storage_chirho: &dyn LedgerStoragePortChirho,
    root_object_digest_chirho: &str,
    expected_identity_chirho: &Gd7WinnerHistoryIdentityChirho,
    control_verifier_chirho: &dyn Gd7ReconciliationVerifierPortChirho,
    ledger_verifier_chirho: &dyn Gd7LedgerRecordVerifierPortChirho,
    mut visit_chirho: VisitChirho,
) -> Result<VerifiedGd7WinnerHistoryChainChirho, Gd7WinnerHistoryRefusalChirho>
where
    VisitChirho: FnMut(&LedgerRecordChirho),
{
    let root_chirho = load_verified_gd7_winner_history_root_chirho(
        storage_chirho,
        root_object_digest_chirho,
        expected_identity_chirho,
        control_verifier_chirho,
    )?;
    let mut current_ref_chirho = Some(root_chirho.root_chirho.oldest_page_ref_chirho.clone());
    let mut expected_index_chirho = root_chirho
        .root_chirho
        .page_count_chirho
        .checked_sub(1)
        .ok_or(Gd7WinnerHistoryRefusalChirho::InvalidRootShapeChirho)?;
    let mut observed_records_chirho = 0_u64;
    let mut older_page_chirho: Option<VerifiedGd7WinnerHistoryPageChirho> = None;

    for page_offset_chirho in 0..root_chirho.root_chirho.page_count_chirho {
        let page_ref_chirho = current_ref_chirho
            .take()
            .ok_or(Gd7WinnerHistoryRefusalChirho::IncompleteChainChirho)?;
        let page_chirho = load_verified_history_page_chirho(
            storage_chirho,
            &page_ref_chirho,
            expected_identity_chirho,
        )?;
        if page_chirho.page_chirho.page_index_chirho != expected_index_chirho
            || (page_offset_chirho == 0) != page_chirho.page_chirho.reached_fork_anchor_chirho
        {
            return Err(Gd7WinnerHistoryRefusalChirho::IncompleteChainChirho);
        }
        if let Some(older_page_chirho) = &older_page_chirho {
            validate_cross_page_transition_chirho(&older_page_chirho.page_chirho, &page_chirho)?;
        }
        for record_chirho in &page_chirho.page_chirho.records_newest_first_chirho {
            verify_ledger_record_signature_chirho(record_chirho, ledger_verifier_chirho)?;
        }
        for record_chirho in page_chirho
            .page_chirho
            .records_newest_first_chirho
            .iter()
            .rev()
        {
            visit_chirho(&record_chirho.record_chirho);
        }
        observed_records_chirho = observed_records_chirho
            .checked_add(
                u64::try_from(page_chirho.page_chirho.records_newest_first_chirho.len())
                    .map_err(|_| Gd7WinnerHistoryRefusalChirho::ArithmeticOverflowChirho)?,
            )
            .ok_or(Gd7WinnerHistoryRefusalChirho::ArithmeticOverflowChirho)?;
        current_ref_chirho = page_chirho.page_chirho.newer_page_ref_chirho.clone();
        expected_index_chirho = expected_index_chirho.saturating_sub(1);
        older_page_chirho = Some(page_chirho);
    }
    if current_ref_chirho.is_some()
        || observed_records_chirho != root_chirho.root_chirho.record_count_chirho
        || older_page_chirho
            .as_ref()
            .is_none_or(|page_chirho| page_chirho.page_chirho.page_index_chirho != 0)
    {
        return Err(Gd7WinnerHistoryRefusalChirho::IncompleteChainChirho);
    }
    Ok(VerifiedGd7WinnerHistoryChainChirho { root_chirho })
}

pub(super) fn load_gd7_winner_history_transfer_page_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    object_digest_chirho: &str,
    expected_identity_chirho: &Gd7WinnerHistoryIdentityChirho,
) -> Result<Gd7WinnerHistoryTransferPageChirho, Gd7WinnerHistoryRefusalChirho> {
    let page_chirho = load_verified_history_page_chirho(
        storage_chirho,
        object_digest_chirho,
        expected_identity_chirho,
    )?;
    transfer_page_from_verified_chirho(page_chirho)
}

pub(super) fn verify_gd7_winner_history_transfer_page_chirho(
    canonical_bytes_chirho: &[u8],
    object_digest_chirho: &str,
    expected_identity_chirho: &Gd7WinnerHistoryIdentityChirho,
) -> Result<Gd7WinnerHistoryTransferPageChirho, Gd7WinnerHistoryRefusalChirho> {
    let page_chirho = verify_page_bytes_chirho(
        canonical_bytes_chirho,
        object_digest_chirho,
        expected_identity_chirho,
    )?;
    transfer_page_from_verified_chirho(page_chirho)
}

fn transfer_page_from_verified_chirho(
    page_chirho: VerifiedGd7WinnerHistoryPageChirho,
) -> Result<Gd7WinnerHistoryTransferPageChirho, Gd7WinnerHistoryRefusalChirho> {
    let canonical_bytes_chirho = canonical_json_chirho(&page_chirho.page_chirho)
        .map_err(|_| Gd7WinnerHistoryRefusalChirho::MalformedPageChirho)?;
    Ok(Gd7WinnerHistoryTransferPageChirho {
        canonical_bytes_chirho,
        page_index_chirho: page_chirho.page_chirho.page_index_chirho,
        next_page_ref_chirho: page_chirho.page_chirho.newer_page_ref_chirho,
    })
}

fn build_history_page_chirho(
    identity_chirho: &Gd7WinnerHistoryIdentityChirho,
    newer_page_chirho: Option<&VerifiedGd7WinnerHistoryPageChirho>,
    suffix_page_chirho: &VerifiedLosingSuffixPageChirho,
    injected_journal_key_id_chirho: &str,
    next_cursor_object_ref_chirho: Option<String>,
) -> Result<Gd7WinnerHistoryPageChirho, Gd7WinnerHistoryRefusalChirho> {
    if suffix_page_chirho
        .records_newest_first_chirho()
        .iter()
        .any(|record_chirho| record_chirho.key_id_chirho != injected_journal_key_id_chirho)
    {
        return Err(Gd7WinnerHistoryRefusalChirho::WrongJournalLabelChirho);
    }
    let records_newest_first_chirho = suffix_page_chirho
        .records_newest_first_chirho()
        .iter()
        .map(|record_chirho| {
            let bytes_chirho = canonical_ledger_record_line_chirho(record_chirho)
                .map_err(|_| Gd7WinnerHistoryRefusalChirho::RecordEncodingChirho)?;
            Ok(Gd7WinnerHistoryRecordChirho {
                record_digest_chirho: stored_line_digest_chirho(&bytes_chirho).0,
                record_chirho: record_chirho.clone(),
            })
        })
        .collect::<Result<Vec<_>, Gd7WinnerHistoryRefusalChirho>>()?;
    let local_record_count_chirho = u64::try_from(records_newest_first_chirho.len())
        .map_err(|_| Gd7WinnerHistoryRefusalChirho::ArithmeticOverflowChirho)?;
    let (page_index_chirho, newer_page_ref_chirho, cumulative_record_count_chirho) =
        if let Some(newer_page_chirho) = newer_page_chirho {
            (
                newer_page_chirho
                    .page_chirho
                    .page_index_chirho
                    .checked_add(1)
                    .ok_or(Gd7WinnerHistoryRefusalChirho::ArithmeticOverflowChirho)?,
                Some(newer_page_chirho.object_digest_chirho.clone()),
                newer_page_chirho
                    .page_chirho
                    .cumulative_record_count_chirho
                    .checked_add(local_record_count_chirho)
                    .ok_or(Gd7WinnerHistoryRefusalChirho::ArithmeticOverflowChirho)?,
            )
        } else {
            (0, None, local_record_count_chirho)
        };
    let page_chirho = Gd7WinnerHistoryPageChirho {
        schema_chirho: GD7_WINNER_HISTORY_PAGE_SCHEMA_V1_CHIRHO.to_owned(),
        identity_chirho: identity_chirho.clone(),
        page_index_chirho,
        newer_page_ref_chirho,
        records_newest_first_chirho,
        next_cursor_object_ref_chirho,
        reached_fork_anchor_chirho: suffix_page_chirho.reached_anchor_chirho(),
        cumulative_record_count_chirho,
    };
    validate_history_page_chirho(&page_chirho, identity_chirho)?;
    if let Some(newer_page_chirho) = newer_page_chirho {
        validate_cross_page_transition_chirho(&page_chirho, newer_page_chirho)?;
    }
    Ok(page_chirho)
}

fn persist_next_cursor_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    suffix_page_chirho: &VerifiedLosingSuffixPageChirho,
) -> Result<Option<String>, Gd7WinnerHistoryRefusalChirho> {
    let Some(cursor_chirho) = suffix_page_chirho.next_cursor_chirho() else {
        return Ok(None);
    };
    let bytes_chirho = cursor_chirho.encode_durable_chirho()?;
    let digest_chirho = digest_bytes_chirho(&bytes_chirho);
    let path_chirho = gd7_winner_history_cursor_path_chirho(&digest_chirho)?;
    persist_immutable_chirho(storage_chirho, &path_chirho, &bytes_chirho)?;
    Ok(Some(digest_chirho))
}

fn persist_history_page_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    page_chirho: Gd7WinnerHistoryPageChirho,
    expected_identity_chirho: &Gd7WinnerHistoryIdentityChirho,
) -> Result<VerifiedGd7WinnerHistoryPageChirho, Gd7WinnerHistoryRefusalChirho> {
    validate_history_page_chirho(&page_chirho, expected_identity_chirho)?;
    let bytes_chirho = canonical_json_chirho(&page_chirho)
        .map_err(|_| Gd7WinnerHistoryRefusalChirho::MalformedPageChirho)?;
    if bytes_chirho.len() > MAX_GD7_WINNER_HISTORY_PAGE_BYTES_CHIRHO {
        return Err(Gd7WinnerHistoryRefusalChirho::OversizedPageChirho);
    }
    let digest_chirho = digest_bytes_chirho(&bytes_chirho);
    let path_chirho = gd7_winner_history_page_path_chirho(&digest_chirho)?;
    persist_immutable_chirho(storage_chirho, &path_chirho, &bytes_chirho)?;
    verify_page_bytes_chirho(&bytes_chirho, &digest_chirho, expected_identity_chirho)
}

fn load_verified_history_page_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    object_digest_chirho: &str,
    expected_identity_chirho: &Gd7WinnerHistoryIdentityChirho,
) -> Result<VerifiedGd7WinnerHistoryPageChirho, Gd7WinnerHistoryRefusalChirho> {
    if !is_lower_hex_digest_chirho(object_digest_chirho) {
        return Err(Gd7WinnerHistoryRefusalChirho::InvalidReferenceChirho);
    }
    let path_chirho = gd7_winner_history_page_path_chirho(object_digest_chirho)?;
    let bytes_chirho = read_bounded_object_chirho(
        storage_chirho,
        &path_chirho,
        MAX_GD7_WINNER_HISTORY_PAGE_BYTES_CHIRHO,
        Gd7WinnerHistoryRefusalChirho::OversizedPageChirho,
    )?;
    verify_page_bytes_chirho(
        &bytes_chirho,
        object_digest_chirho,
        expected_identity_chirho,
    )
}

fn verify_page_bytes_chirho(
    bytes_chirho: &[u8],
    expected_object_digest_chirho: &str,
    expected_identity_chirho: &Gd7WinnerHistoryIdentityChirho,
) -> Result<VerifiedGd7WinnerHistoryPageChirho, Gd7WinnerHistoryRefusalChirho> {
    if digest_bytes_chirho(bytes_chirho) != expected_object_digest_chirho {
        return Err(Gd7WinnerHistoryRefusalChirho::ObjectDigestMismatchChirho);
    }
    let page_chirho: Gd7WinnerHistoryPageChirho = parse_json_chirho(
        bytes_chirho,
        Gd7WinnerHistoryRefusalChirho::MalformedPageChirho,
    )?;
    validate_history_page_chirho(&page_chirho, expected_identity_chirho)?;
    if canonical_json_chirho(&page_chirho)
        .map_err(|_| Gd7WinnerHistoryRefusalChirho::MalformedPageChirho)?
        != bytes_chirho
    {
        return Err(Gd7WinnerHistoryRefusalChirho::NonCanonicalPageChirho);
    }
    Ok(VerifiedGd7WinnerHistoryPageChirho {
        object_digest_chirho: expected_object_digest_chirho.to_owned(),
        page_chirho,
    })
}

fn persist_history_root_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    signer_chirho: &dyn Gd7ReconciliationSignerPortChirho,
    identity_chirho: &Gd7WinnerHistoryIdentityChirho,
    oldest_page_chirho: &VerifiedGd7WinnerHistoryPageChirho,
) -> Result<VerifiedGd7WinnerHistoryRootChirho, Gd7WinnerHistoryRefusalChirho> {
    if signer_chirho.key_id_chirho()
        != identity_chirho
            .reconciliation_identity_chirho
            .winner_node_chirho
    {
        return Err(Gd7WinnerHistoryRefusalChirho::WrongControlSignerChirho);
    }
    let mut root_chirho = Gd7WinnerHistoryRootChirho {
        schema_chirho: GD7_WINNER_HISTORY_ROOT_SCHEMA_V1_CHIRHO.to_owned(),
        identity_chirho: identity_chirho.clone(),
        oldest_page_ref_chirho: oldest_page_chirho.object_digest_chirho.clone(),
        page_count_chirho: oldest_page_chirho
            .page_chirho
            .page_index_chirho
            .checked_add(1)
            .ok_or(Gd7WinnerHistoryRefusalChirho::ArithmeticOverflowChirho)?,
        record_count_chirho: oldest_page_chirho
            .page_chirho
            .cumulative_record_count_chirho,
        key_id_chirho: signer_chirho.key_id_chirho(),
        sig_chirho: String::new(),
    };
    validate_history_root_shape_chirho(&root_chirho, identity_chirho, false)?;
    let unsigned_line_chirho = canonical_string_chirho(&root_chirho)
        .map_err(|_| Gd7WinnerHistoryRefusalChirho::SigningChirho)?;
    root_chirho.sig_chirho = signer_chirho
        .sign_chirho(&unsigned_line_chirho)
        .map_err(|_| Gd7WinnerHistoryRefusalChirho::SigningChirho)?;
    validate_history_root_shape_chirho(&root_chirho, identity_chirho, true)?;
    let bytes_chirho = canonical_json_chirho(&root_chirho)
        .map_err(|_| Gd7WinnerHistoryRefusalChirho::MalformedRootChirho)?;
    if bytes_chirho.len() > MAX_GD7_WINNER_HISTORY_ROOT_BYTES_CHIRHO {
        return Err(Gd7WinnerHistoryRefusalChirho::OversizedRootChirho);
    }
    let digest_chirho = digest_bytes_chirho(&bytes_chirho);
    let path_chirho = gd7_winner_history_root_path_chirho(&digest_chirho)?;
    persist_immutable_chirho(storage_chirho, &path_chirho, &bytes_chirho)?;
    verify_root_bytes_chirho(
        &bytes_chirho,
        &digest_chirho,
        identity_chirho,
        signer_chirho,
    )
}

fn verify_root_bytes_chirho(
    bytes_chirho: &[u8],
    expected_object_digest_chirho: &str,
    expected_identity_chirho: &Gd7WinnerHistoryIdentityChirho,
    verifier_chirho: &dyn Gd7ReconciliationVerifierPortChirho,
) -> Result<VerifiedGd7WinnerHistoryRootChirho, Gd7WinnerHistoryRefusalChirho> {
    if digest_bytes_chirho(bytes_chirho) != expected_object_digest_chirho {
        return Err(Gd7WinnerHistoryRefusalChirho::ObjectDigestMismatchChirho);
    }
    let root_chirho: Gd7WinnerHistoryRootChirho = parse_json_chirho(
        bytes_chirho,
        Gd7WinnerHistoryRefusalChirho::MalformedRootChirho,
    )?;
    validate_history_root_shape_chirho(&root_chirho, expected_identity_chirho, true)?;
    if canonical_json_chirho(&root_chirho)
        .map_err(|_| Gd7WinnerHistoryRefusalChirho::MalformedRootChirho)?
        != bytes_chirho
    {
        return Err(Gd7WinnerHistoryRefusalChirho::NonCanonicalRootChirho);
    }
    if root_chirho.key_id_chirho != verifier_chirho.key_id_chirho() {
        return Err(Gd7WinnerHistoryRefusalChirho::WrongControlSignerChirho);
    }
    let mut unsigned_chirho = root_chirho.clone();
    let signature_chirho = std::mem::take(&mut unsigned_chirho.sig_chirho);
    let unsigned_line_chirho = canonical_string_chirho(&unsigned_chirho)
        .map_err(|_| Gd7WinnerHistoryRefusalChirho::MalformedRootChirho)?;
    if !verifier_chirho.verify_chirho(&unsigned_line_chirho, &signature_chirho) {
        return Err(Gd7WinnerHistoryRefusalChirho::InvalidRootSignatureChirho);
    }
    Ok(VerifiedGd7WinnerHistoryRootChirho {
        object_digest_chirho: expected_object_digest_chirho.to_owned(),
        root_chirho,
    })
}

fn validate_history_identity_chirho(
    identity_chirho: &Gd7WinnerHistoryIdentityChirho,
) -> Result<(), Gd7WinnerHistoryRefusalChirho> {
    if !validate_identity_chirho(&identity_chirho.reconciliation_identity_chirho)
        || !is_lower_hex_digest_chirho(&identity_chirho.reconciliation_identity_digest_chirho)
        || !is_lower_hex_digest_chirho(&identity_chirho.winner_handoff_attempt_digest_chirho)
        || gd7_reconciliation_identity_digest_chirho(
            &identity_chirho.reconciliation_identity_chirho,
        )
        .map_err(|_| Gd7WinnerHistoryRefusalChirho::InvalidIdentityChirho)?
            != identity_chirho.reconciliation_identity_digest_chirho
    {
        return Err(Gd7WinnerHistoryRefusalChirho::InvalidIdentityChirho);
    }
    Ok(())
}

fn validate_history_page_chirho(
    page_chirho: &Gd7WinnerHistoryPageChirho,
    expected_identity_chirho: &Gd7WinnerHistoryIdentityChirho,
) -> Result<(), Gd7WinnerHistoryRefusalChirho> {
    validate_history_identity_chirho(&page_chirho.identity_chirho)?;
    let records_chirho = &page_chirho.records_newest_first_chirho;
    if page_chirho.schema_chirho != GD7_WINNER_HISTORY_PAGE_SCHEMA_V1_CHIRHO
        || page_chirho.identity_chirho != *expected_identity_chirho
        || records_chirho.is_empty()
        || records_chirho.len() > MAX_LOSING_SUFFIX_PAGE_RECORDS_CHIRHO
        || (page_chirho.page_index_chirho == 0) != page_chirho.newer_page_ref_chirho.is_none()
        || page_chirho
            .newer_page_ref_chirho
            .as_deref()
            .is_some_and(|digest_chirho| !is_lower_hex_digest_chirho(digest_chirho))
        || page_chirho.reached_fork_anchor_chirho
            == page_chirho.next_cursor_object_ref_chirho.is_some()
        || page_chirho
            .next_cursor_object_ref_chirho
            .as_deref()
            .is_some_and(|digest_chirho| !is_lower_hex_digest_chirho(digest_chirho))
        || page_chirho.cumulative_record_count_chirho
            < u64::try_from(records_chirho.len())
                .map_err(|_| Gd7WinnerHistoryRefusalChirho::ArithmeticOverflowChirho)?
    {
        return Err(Gd7WinnerHistoryRefusalChirho::InvalidPageShapeChirho);
    }

    for (record_index_chirho, record_chirho) in records_chirho.iter().enumerate() {
        validate_record_digest_chirho(record_chirho)?;
        if u64::from(
            split_writer_epoch_chirho(record_chirho.record_chirho.epoch_chirho).geo_term_chirho,
        ) != page_chirho
            .identity_chirho
            .reconciliation_identity_chirho
            .winner_term_chirho
        {
            return Err(Gd7WinnerHistoryRefusalChirho::RecordChainMismatchChirho);
        }
        if let Some(older_record_chirho) = records_chirho.get(record_index_chirho + 1) {
            if record_chirho.record_chirho.seq_chirho
                != older_record_chirho
                    .record_chirho
                    .seq_chirho
                    .checked_add(1)
                    .ok_or(Gd7WinnerHistoryRefusalChirho::ArithmeticOverflowChirho)?
                || record_chirho.record_chirho.prev_chirho.0
                    != older_record_chirho.record_digest_chirho
            {
                return Err(Gd7WinnerHistoryRefusalChirho::RecordChainMismatchChirho);
            }
        }
    }

    let reconciliation_chirho = &page_chirho.identity_chirho.reconciliation_identity_chirho;
    let newest_record_chirho = records_chirho
        .first()
        .ok_or(Gd7WinnerHistoryRefusalChirho::InvalidPageShapeChirho)?;
    if page_chirho.page_index_chirho == 0
        && (newest_record_chirho.record_chirho.seq_chirho
            != reconciliation_chirho.winner_journal_tail_chirho.seq_chirho
            || newest_record_chirho.record_digest_chirho
                != reconciliation_chirho
                    .winner_journal_tail_chirho
                    .record_digest_chirho)
    {
        return Err(Gd7WinnerHistoryRefusalChirho::RecordChainMismatchChirho);
    }
    if page_chirho.reached_fork_anchor_chirho {
        validate_oldest_record_against_fork_chirho(
            records_chirho
                .last()
                .ok_or(Gd7WinnerHistoryRefusalChirho::InvalidPageShapeChirho)?,
            &reconciliation_chirho.fork_chirho,
        )?;
    }
    Ok(())
}

fn validate_cross_page_transition_chirho(
    older_page_chirho: &Gd7WinnerHistoryPageChirho,
    newer_page_chirho: &VerifiedGd7WinnerHistoryPageChirho,
) -> Result<(), Gd7WinnerHistoryRefusalChirho> {
    if older_page_chirho.newer_page_ref_chirho.as_deref()
        != Some(&newer_page_chirho.object_digest_chirho)
        || older_page_chirho.page_index_chirho
            != newer_page_chirho
                .page_chirho
                .page_index_chirho
                .checked_add(1)
                .ok_or(Gd7WinnerHistoryRefusalChirho::ArithmeticOverflowChirho)?
        || older_page_chirho.cumulative_record_count_chirho
            != newer_page_chirho
                .page_chirho
                .cumulative_record_count_chirho
                .checked_add(
                    u64::try_from(older_page_chirho.records_newest_first_chirho.len())
                        .map_err(|_| Gd7WinnerHistoryRefusalChirho::ArithmeticOverflowChirho)?,
                )
                .ok_or(Gd7WinnerHistoryRefusalChirho::ArithmeticOverflowChirho)?
    {
        return Err(Gd7WinnerHistoryRefusalChirho::IncompleteChainChirho);
    }
    let newer_boundary_chirho = newer_page_chirho
        .page_chirho
        .records_newest_first_chirho
        .last()
        .ok_or(Gd7WinnerHistoryRefusalChirho::InvalidPageShapeChirho)?;
    let older_boundary_chirho = older_page_chirho
        .records_newest_first_chirho
        .first()
        .ok_or(Gd7WinnerHistoryRefusalChirho::InvalidPageShapeChirho)?;
    if newer_boundary_chirho.record_chirho.seq_chirho
        != older_boundary_chirho
            .record_chirho
            .seq_chirho
            .checked_add(1)
            .ok_or(Gd7WinnerHistoryRefusalChirho::ArithmeticOverflowChirho)?
        || newer_boundary_chirho.record_chirho.prev_chirho.0
            != older_boundary_chirho.record_digest_chirho
    {
        return Err(Gd7WinnerHistoryRefusalChirho::RecordChainMismatchChirho);
    }
    Ok(())
}

fn validate_oldest_record_against_fork_chirho(
    oldest_record_chirho: &Gd7WinnerHistoryRecordChirho,
    fork_chirho: &Gd7ForkCoordinateChirho,
) -> Result<(), Gd7WinnerHistoryRefusalChirho> {
    let anchor_chirho = oldest_record_chirho
        .record_chirho
        .anchor_chirho
        .as_ref()
        .ok_or(Gd7WinnerHistoryRefusalChirho::RecordChainMismatchChirho)?;
    if oldest_record_chirho.record_chirho.seq_chirho
        != fork_chirho
            .seq_chirho
            .checked_add(1)
            .ok_or(Gd7WinnerHistoryRefusalChirho::ArithmeticOverflowChirho)?
        || oldest_record_chirho.record_chirho.prev_chirho.0 != fork_chirho.record_digest_chirho
        || anchor_chirho.inherited_epoch_chirho != fork_chirho.epoch_chirho
        || anchor_chirho.inherited_seq_chirho != fork_chirho.seq_chirho
        || anchor_chirho.inherited_digest_chirho.0 != fork_chirho.record_digest_chirho
    {
        return Err(Gd7WinnerHistoryRefusalChirho::RecordChainMismatchChirho);
    }
    Ok(())
}

fn validate_record_digest_chirho(
    record_chirho: &Gd7WinnerHistoryRecordChirho,
) -> Result<(), Gd7WinnerHistoryRefusalChirho> {
    if !is_lower_hex_digest_chirho(&record_chirho.record_digest_chirho) {
        return Err(Gd7WinnerHistoryRefusalChirho::InvalidPageShapeChirho);
    }
    let bytes_chirho = canonical_ledger_record_line_chirho(&record_chirho.record_chirho)
        .map_err(|_| Gd7WinnerHistoryRefusalChirho::RecordEncodingChirho)?;
    if stored_line_digest_chirho(&bytes_chirho).0 != record_chirho.record_digest_chirho {
        return Err(Gd7WinnerHistoryRefusalChirho::ObjectDigestMismatchChirho);
    }
    Ok(())
}

fn verify_ledger_record_signature_chirho(
    record_chirho: &Gd7WinnerHistoryRecordChirho,
    verifier_chirho: &dyn Gd7LedgerRecordVerifierPortChirho,
) -> Result<(), Gd7WinnerHistoryRefusalChirho> {
    if record_chirho.record_chirho.key_id_chirho != verifier_chirho.key_id_chirho() {
        return Err(Gd7WinnerHistoryRefusalChirho::WrongJournalLabelChirho);
    }
    let signed_content_chirho =
        ledger_record_signed_content_line_chirho(&record_chirho.record_chirho)
            .map_err(|_| Gd7WinnerHistoryRefusalChirho::RecordEncodingChirho)?;
    if !verifier_chirho.verify_chirho(
        &signed_content_chirho,
        &record_chirho.record_chirho.sig_chirho,
    ) {
        return Err(Gd7WinnerHistoryRefusalChirho::InvalidLedgerSignatureChirho);
    }
    Ok(())
}

fn validate_history_root_shape_chirho(
    root_chirho: &Gd7WinnerHistoryRootChirho,
    expected_identity_chirho: &Gd7WinnerHistoryIdentityChirho,
    require_signature_chirho: bool,
) -> Result<(), Gd7WinnerHistoryRefusalChirho> {
    validate_history_identity_chirho(&root_chirho.identity_chirho)?;
    if root_chirho.schema_chirho != GD7_WINNER_HISTORY_ROOT_SCHEMA_V1_CHIRHO
        || root_chirho.identity_chirho != *expected_identity_chirho
        || !is_lower_hex_digest_chirho(&root_chirho.oldest_page_ref_chirho)
        || root_chirho.page_count_chirho == 0
        || root_chirho.record_count_chirho < root_chirho.page_count_chirho
        || root_chirho.key_id_chirho
            != root_chirho
                .identity_chirho
                .reconciliation_identity_chirho
                .winner_node_chirho
        || if require_signature_chirho {
            !validate_key_and_signature_chirho(&root_chirho.key_id_chirho, &root_chirho.sig_chirho)
        } else {
            !root_chirho.sig_chirho.is_empty()
        }
    {
        return Err(Gd7WinnerHistoryRefusalChirho::InvalidRootShapeChirho);
    }
    Ok(())
}

fn content_addressed_path_chirho(
    family_chirho: &str,
    object_digest_chirho: &str,
    extension_chirho: &str,
) -> Result<StoragePathChirho, Gd7WinnerHistoryRefusalChirho> {
    if !is_lower_hex_digest_chirho(object_digest_chirho) {
        return Err(Gd7WinnerHistoryRefusalChirho::InvalidReferenceChirho);
    }
    Ok(StoragePathChirho::new_chirho(format!(
        "{GD7_RECONCILIATION_NAMESPACE_CHIRHO}/{family_chirho}/{}/{}/{object_digest_chirho}.{extension_chirho}",
        &object_digest_chirho[..2],
        &object_digest_chirho[2..4],
    )))
}

fn persist_immutable_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    path_chirho: &StoragePathChirho,
    bytes_chirho: &[u8],
) -> Result<(), Gd7WinnerHistoryRefusalChirho> {
    match storage_chirho
        .create_durable_chirho(path_chirho, bytes_chirho)
        .map_err(|_| Gd7WinnerHistoryRefusalChirho::StorageChirho)?
    {
        CreateDurableOutcomeChirho::CreatedChirho => Ok(()),
        CreateDurableOutcomeChirho::AlreadyExistsChirho => {
            let existing_chirho = read_bounded_object_chirho(
                storage_chirho,
                path_chirho,
                bytes_chirho.len(),
                Gd7WinnerHistoryRefusalChirho::ImmutableCollisionChirho,
            )?;
            if existing_chirho == bytes_chirho {
                Ok(())
            } else {
                Err(Gd7WinnerHistoryRefusalChirho::ImmutableCollisionChirho)
            }
        }
    }
}

fn read_bounded_object_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    path_chirho: &StoragePathChirho,
    maximum_chirho: usize,
    oversized_chirho: Gd7WinnerHistoryRefusalChirho,
) -> Result<Vec<u8>, Gd7WinnerHistoryRefusalChirho> {
    let length_chirho = storage_chirho
        .object_len_chirho(path_chirho)
        .map_err(|_| Gd7WinnerHistoryRefusalChirho::StorageChirho)?
        .ok_or(Gd7WinnerHistoryRefusalChirho::MissingObjectChirho)?;
    if length_chirho > maximum_chirho as u64 {
        return Err(oversized_chirho);
    }
    let bytes_chirho = if length_chirho == 0 {
        Vec::new()
    } else {
        storage_chirho
            .read_exact_range_chirho(path_chirho, 0, length_chirho)
            .map_err(|_| Gd7WinnerHistoryRefusalChirho::StorageChirho)?
    };
    if bytes_chirho.len() != length_chirho as usize
        || storage_chirho
            .object_len_chirho(path_chirho)
            .map_err(|_| Gd7WinnerHistoryRefusalChirho::StorageChirho)?
            != Some(length_chirho)
    {
        return Err(Gd7WinnerHistoryRefusalChirho::StorageChirho);
    }
    Ok(bytes_chirho)
}

fn parse_json_chirho<ValueChirho: DeserializeOwned>(
    bytes_chirho: &[u8],
    malformed_chirho: Gd7WinnerHistoryRefusalChirho,
) -> Result<ValueChirho, Gd7WinnerHistoryRefusalChirho> {
    serde_json::from_slice(bytes_chirho).map_err(|_| malformed_chirho)
}

fn canonical_json_chirho(value_chirho: &impl Serialize) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(value_chirho)
}

fn canonical_string_chirho(value_chirho: &impl Serialize) -> Result<String, serde_json::Error> {
    serde_json::to_string(value_chirho)
}

fn digest_bytes_chirho(bytes_chirho: &[u8]) -> String {
    blake3::hash(bytes_chirho).to_hex().to_string()
}
