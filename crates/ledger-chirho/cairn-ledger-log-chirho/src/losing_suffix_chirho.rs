// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Bounded authenticated reverse traversal of one frozen losing journal suffix.
//!
//! Sealed history is addressed through the signed predecessor index written before each manifest
//! append. This path never scans the manifest or lists storage: each sealed hop is a direct digest
//! lookup, and each record page reads at most its body-byte budget plus bounded JSONL framing.
//! Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/cf8-gd7-deposed-fork-reconciliation-design-chirho.md`.

mod frozen_reader_chirho;

pub use frozen_reader_chirho::{
    ExpectedLosingTailFloorChirho, FrozenLosingJournalReaderChirho,
    VerifiedLosingTailFloorRelationChirho,
};

use crate::journal_chirho::{verify_tail_signature_chirho, LedgerJournalChirho};
use crate::segment_adapter_chirho::{
    SegmentContinuityOverLedgerSignerPortChirho, SegmentStorageOverLedgerPortChirho,
};
use cairn_ledger_model_chirho::ids_chirho::DigestChirho;
use cairn_ledger_model_chirho::record_chirho::LedgerRecordChirho;
use cairn_ledger_model_chirho::wire_chirho::{
    ledger_record_signed_content_line_chirho, parse_canonical_ledger_journal_line_chirho,
    stored_line_digest_chirho, LedgerJournalLineChirho,
};
use cairn_seqlog_chirho::segment_chirho::manifest_chirho::SegmentManifestEntryChirho;
use cairn_seqlog_chirho::segment_chirho::manifest_head_chirho::try_manifest_head_fast_path_chirho;
use cairn_seqlog_chirho::segment_chirho::paths_chirho::SegmentPathsChirho;
use cairn_seqlog_chirho::segment_chirho::predecessor_index_chirho::load_predecessor_index_entry_chirho;
use cairn_seqlog_chirho::segment_chirho::storage_chirho::{
    SegmentPathChirho, SegmentStorageChirho,
};
use cairn_seqlog_chirho::segment_chirho::LogIdentityChirho;
use serde::{Deserialize, Serialize};

/// Independent hard cap on records returned by one verified reverse page.
pub const MAX_LOSING_SUFFIX_PAGE_RECORDS_CHIRHO: usize = 256;
/// Independent hard cap on canonical record BODY bytes returned by one verified reverse page.
pub const MAX_LOSING_SUFFIX_PAGE_BYTES_CHIRHO: usize = 4 * 1024 * 1024;
/// Hard cap on one durable signed continuation.
pub const MAX_LOSING_SUFFIX_CURSOR_BYTES_CHIRHO: usize = 4 * 1024;
const LOSING_SUFFIX_CURSOR_SCHEMA_CHIRHO: &str = "ledger-losing-suffix-cursor-v1-chirho";
const BLAKE3_HEX_DIGEST_BYTES_CHIRHO: usize = 64;
const INITIAL_REVERSE_READ_BYTES_CHIRHO: usize = 16 * 1024;
const MAX_CURRENT_LOSING_TAIL_LINE_BYTES_CHIRHO: usize = MAX_LOSING_SUFFIX_PAGE_BYTES_CHIRHO;

/// The immutable journal identity every page and cursor remains bound to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LosingSuffixJournalIdentityChirho {
    genesis_digest_chirho: DigestChirho,
}

impl LosingSuffixJournalIdentityChirho {
    pub fn new_chirho(genesis_digest_chirho: DigestChirho) -> Self {
        Self {
            genesis_digest_chirho,
        }
    }

    pub fn genesis_digest_chirho(&self) -> &DigestChirho {
        &self.genesis_digest_chirho
    }
}

/// One exact signed-record coordinate. The anchor itself is excluded from returned records.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LosingSuffixCoordinateChirho {
    seq_chirho: u64,
    record_digest_chirho: DigestChirho,
}

impl LosingSuffixCoordinateChirho {
    pub fn new_chirho(seq_chirho: u64, record_digest_chirho: DigestChirho) -> Self {
        Self {
            seq_chirho,
            record_digest_chirho,
        }
    }

    pub fn seq_chirho(&self) -> u64 {
        self.seq_chirho
    }

    pub fn record_digest_chirho(&self) -> &DigestChirho {
        &self.record_digest_chirho
    }
}

/// Opaque exact tail snapshot minted only from a fully verified open journal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedLosingJournalTailChirho {
    identity_chirho: LosingSuffixJournalIdentityChirho,
    coordinate_chirho: LosingSuffixCoordinateChirho,
    record_epoch_chirho: u64,
}

impl VerifiedLosingJournalTailChirho {
    pub fn identity_chirho(&self) -> &LosingSuffixJournalIdentityChirho {
        &self.identity_chirho
    }

    pub fn coordinate_chirho(&self) -> &LosingSuffixCoordinateChirho {
        &self.coordinate_chirho
    }

    pub fn record_epoch_chirho(&self) -> u64 {
        self.record_epoch_chirho
    }
}

/// The bounded reverse-reading surface used by reconciliation.
///
/// Production may supply either a normally opened journal or the held-only physical-cut reader.
/// Callers never receive aggregate balances or mutation methods through this interface.
pub trait LosingSuffixReaderChirho {
    /// The label carried by the journal verifier injected by the composition root.
    ///
    /// This remains label-only metadata. Trust selection happens when the reader verifies records
    /// against its injected signer, never from a record's self-declared `key_id_chirho`.
    fn injected_journal_key_id_chirho(&self) -> String;

    fn revalidate_current_losing_tail_chirho(
        &self,
    ) -> Result<VerifiedLosingJournalTailChirho, LosingSuffixReadErrorChirho>;

    fn decode_verified_losing_suffix_cursor_chirho(
        &self,
        bytes_chirho: &[u8],
    ) -> Result<LosingSuffixCursorChirho, LosingSuffixReadErrorChirho>;

    fn read_verified_losing_suffix_page_chirho(
        &self,
        request_chirho: &LosingSuffixPageRequestChirho,
    ) -> Result<VerifiedLosingSuffixPageChirho, LosingSuffixReadErrorChirho>;
}

impl LedgerJournalChirho<'_> {
    /// Snapshot the exact committed tail epoch/sequence/digest from this verified journal.
    ///
    /// This intentionally uses `last_recorded_epoch_chirho`, not the current lease epoch, because
    /// a lease may advance before its first record commits.
    pub fn verified_losing_tail_chirho(&self) -> VerifiedLosingJournalTailChirho {
        VerifiedLosingJournalTailChirho {
            identity_chirho: LosingSuffixJournalIdentityChirho::new_chirho(
                self.genesis_digest_chirho.clone(),
            ),
            coordinate_chirho: LosingSuffixCoordinateChirho::new_chirho(
                self.tail_seq_chirho,
                self.tail_digest_chirho.clone(),
            ),
            record_epoch_chirho: self.last_recorded_epoch_chirho,
        }
    }
}

impl LosingSuffixReaderChirho for LedgerJournalChirho<'_> {
    fn injected_journal_key_id_chirho(&self) -> String {
        self.signer_chirho.key_id_chirho()
    }

    fn revalidate_current_losing_tail_chirho(
        &self,
    ) -> Result<VerifiedLosingJournalTailChirho, LosingSuffixReadErrorChirho> {
        LedgerJournalChirho::revalidate_current_losing_tail_chirho(self)
    }

    fn decode_verified_losing_suffix_cursor_chirho(
        &self,
        bytes_chirho: &[u8],
    ) -> Result<LosingSuffixCursorChirho, LosingSuffixReadErrorChirho> {
        LedgerJournalChirho::decode_verified_losing_suffix_cursor_chirho(self, bytes_chirho)
    }

    fn read_verified_losing_suffix_page_chirho(
        &self,
        request_chirho: &LosingSuffixPageRequestChirho,
    ) -> Result<VerifiedLosingSuffixPageChirho, LosingSuffixReadErrorChirho> {
        LedgerJournalChirho::read_verified_losing_suffix_page_chirho(self, request_chirho)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "source_chirho", deny_unknown_fields)]
enum LosingSuffixCursorSourceChirho {
    ActiveChirho {
        end_offset_chirho: u64,
        predecessor_manifest_entry_digest_chirho: Option<String>,
    },
    SealedChirho {
        manifest_entry_digest_chirho: String,
        end_offset_chirho: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LosingSuffixCursorPayloadChirho {
    schema_chirho: String,
    key_id_chirho: String,
    identity_chirho: LosingSuffixJournalIdentityChirho,
    frozen_tail_chirho: LosingSuffixCoordinateChirho,
    exact_anchor_chirho: LosingSuffixCoordinateChirho,
    next_seq_chirho: u64,
    expected_digest_chirho: DigestChirho,
    source_chirho: LosingSuffixCursorSourceChirho,
}

/// Opaque, signed continuation minted only by a verified page.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LosingSuffixCursorChirho {
    payload_chirho: LosingSuffixCursorPayloadChirho,
    signature_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LosingSuffixCursorWireChirho {
    payload_chirho: LosingSuffixCursorPayloadChirho,
    signature_chirho: String,
}

impl LosingSuffixCursorChirho {
    /// Encode this signed cursor as bounded canonical durable bytes.
    pub fn encode_durable_chirho(&self) -> Result<Vec<u8>, LosingSuffixReadErrorChirho> {
        validate_cursor_payload_chirho(&self.payload_chirho)?;
        canonical_cursor_wire_chirho(self)
    }

    fn is_bound_to_request_chirho(&self, request_chirho: &LosingSuffixPageRequestChirho) -> bool {
        self.payload_chirho.identity_chirho == request_chirho.identity_chirho
            && self.payload_chirho.frozen_tail_chirho == request_chirho.frozen_tail_chirho
            && self.payload_chirho.exact_anchor_chirho == request_chirho.exact_anchor_chirho
    }
}

/// One bounded reverse-page request. `None` starts at the frozen tail.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LosingSuffixPageRequestChirho {
    identity_chirho: LosingSuffixJournalIdentityChirho,
    frozen_tail_chirho: LosingSuffixCoordinateChirho,
    exact_anchor_chirho: LosingSuffixCoordinateChirho,
    cursor_chirho: Option<LosingSuffixCursorChirho>,
    max_records_chirho: usize,
    max_bytes_chirho: usize,
}

impl LosingSuffixPageRequestChirho {
    pub fn new_chirho(
        identity_chirho: LosingSuffixJournalIdentityChirho,
        frozen_tail_chirho: LosingSuffixCoordinateChirho,
        exact_anchor_chirho: LosingSuffixCoordinateChirho,
        max_records_chirho: usize,
        max_bytes_chirho: usize,
    ) -> Self {
        Self {
            identity_chirho,
            frozen_tail_chirho,
            exact_anchor_chirho,
            cursor_chirho: None,
            max_records_chirho,
            max_bytes_chirho,
        }
    }

    pub fn with_cursor_chirho(mut self, cursor_chirho: LosingSuffixCursorChirho) -> Self {
        self.cursor_chirho = Some(cursor_chirho);
        self
    }
}

/// A page whose records have passed canonical, signature, sequence, digest-chain, and anchor checks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedLosingSuffixPageChirho {
    identity_chirho: LosingSuffixJournalIdentityChirho,
    frozen_tail_chirho: LosingSuffixCoordinateChirho,
    exact_anchor_chirho: LosingSuffixCoordinateChirho,
    records_newest_first_chirho: Vec<LedgerRecordChirho>,
    encoded_record_bytes_chirho: usize,
    next_cursor_chirho: Option<LosingSuffixCursorChirho>,
    reached_anchor_chirho: bool,
}

impl VerifiedLosingSuffixPageChirho {
    pub fn identity_chirho(&self) -> &LosingSuffixJournalIdentityChirho {
        &self.identity_chirho
    }

    pub fn frozen_tail_chirho(&self) -> &LosingSuffixCoordinateChirho {
        &self.frozen_tail_chirho
    }

    pub fn exact_anchor_chirho(&self) -> &LosingSuffixCoordinateChirho {
        &self.exact_anchor_chirho
    }

    pub fn records_newest_first_chirho(&self) -> &[LedgerRecordChirho] {
        &self.records_newest_first_chirho
    }

    pub fn encoded_record_bytes_chirho(&self) -> usize {
        self.encoded_record_bytes_chirho
    }

    pub fn next_cursor_chirho(&self) -> Option<&LosingSuffixCursorChirho> {
        self.next_cursor_chirho.as_ref()
    }

    pub fn reached_anchor_chirho(&self) -> bool {
        self.reached_anchor_chirho
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LosingSuffixPageLimitChirho {
    RecordsChirho,
    BytesChirho,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LosingSuffixIdentityFieldChirho {
    GenesisDigestChirho,
    FrozenTailDigestChirho,
    AnchorDigestChirho,
    ManifestTailDigestChirho,
}

/// Typed fail-closed refusal from the bounded losing-suffix reader.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LosingSuffixReadErrorChirho {
    InvalidPageLimitChirho {
        limit_chirho: LosingSuffixPageLimitChirho,
        requested_chirho: usize,
        maximum_chirho: usize,
    },
    InvalidIdentityFieldChirho {
        field_chirho: LosingSuffixIdentityFieldChirho,
        observed_bytes_chirho: usize,
    },
    JournalIdentityMismatchChirho,
    FrozenTailMismatchChirho,
    AnchorAfterFrozenTailChirho,
    AnchorDigestMismatchAtFrozenTailChirho,
    AnchorDigestMismatchChirho,
    CursorContinuityMismatchChirho,
    CursorBytesTooLargeChirho {
        observed_chirho: usize,
        maximum_chirho: usize,
    },
    CursorMalformedChirho {
        detail_chirho: String,
    },
    CursorNonCanonicalChirho,
    CursorSignatureInvalidChirho,
    StorageChirho {
        detail_chirho: String,
    },
    PredecessorIndexChirho {
        digest_chirho: String,
        detail_chirho: String,
    },
    ActiveLengthMismatchChirho {
        expected_chirho: u64,
        observed_chirho: Option<u64>,
    },
    PendingRotationChirho,
    SealStateMismatchChirho {
        detail_chirho: String,
    },
    TailLineBytesTooLargeChirho {
        observed_chirho: u64,
        maximum_chirho: usize,
    },
    TailEpochMismatchChirho {
        expected_chirho: u64,
        observed_chirho: u64,
    },
    SegmentLengthMismatchChirho {
        digest_chirho: String,
        expected_chirho: u64,
        observed_chirho: Option<u64>,
    },
    SegmentBoundaryMismatchChirho {
        detail_chirho: String,
    },
    RecordExceedsPageBytesChirho {
        seq_chirho: u64,
        maximum_chirho: usize,
    },
    RecordEncodingChirho {
        expected_seq_chirho: u64,
        detail_chirho: String,
    },
    RecordSignatureInvalidChirho {
        seq_chirho: u64,
    },
    RecordDigestMismatchChirho {
        seq_chirho: u64,
    },
    RecordSequenceMismatchChirho {
        expected_chirho: u64,
        observed_chirho: u64,
    },
    SegmentChainEndedBeforeAnchorChirho,
    /// Retained for Rust API compatibility with the pre-index refusal contract.
    SegmentPredecessorIndexRequiredChirho {
        manifest_tail_entry_digest_chirho: Option<String>,
    },
}

fn is_blake3_hex_digest_chirho(value_chirho: &str) -> bool {
    value_chirho.len() == BLAKE3_HEX_DIGEST_BYTES_CHIRHO
        && value_chirho
            .as_bytes()
            .iter()
            .all(|byte_chirho| byte_chirho.is_ascii_digit() || (b'a'..=b'f').contains(byte_chirho))
}

fn validate_identity_digest_chirho(
    field_chirho: LosingSuffixIdentityFieldChirho,
    digest_chirho: &DigestChirho,
) -> Result<(), LosingSuffixReadErrorChirho> {
    if !is_blake3_hex_digest_chirho(&digest_chirho.0) {
        return Err(LosingSuffixReadErrorChirho::InvalidIdentityFieldChirho {
            field_chirho,
            observed_bytes_chirho: digest_chirho.0.len(),
        });
    }
    Ok(())
}

fn validate_request_chirho(
    request_chirho: &LosingSuffixPageRequestChirho,
) -> Result<(), LosingSuffixReadErrorChirho> {
    validate_limit_chirho(
        LosingSuffixPageLimitChirho::RecordsChirho,
        request_chirho.max_records_chirho,
        MAX_LOSING_SUFFIX_PAGE_RECORDS_CHIRHO,
    )?;
    validate_limit_chirho(
        LosingSuffixPageLimitChirho::BytesChirho,
        request_chirho.max_bytes_chirho,
        MAX_LOSING_SUFFIX_PAGE_BYTES_CHIRHO,
    )?;
    validate_identity_digest_chirho(
        LosingSuffixIdentityFieldChirho::GenesisDigestChirho,
        &request_chirho.identity_chirho.genesis_digest_chirho,
    )?;
    validate_identity_digest_chirho(
        LosingSuffixIdentityFieldChirho::FrozenTailDigestChirho,
        &request_chirho.frozen_tail_chirho.record_digest_chirho,
    )?;
    validate_identity_digest_chirho(
        LosingSuffixIdentityFieldChirho::AnchorDigestChirho,
        &request_chirho.exact_anchor_chirho.record_digest_chirho,
    )
}

fn validate_limit_chirho(
    limit_chirho: LosingSuffixPageLimitChirho,
    requested_chirho: usize,
    maximum_chirho: usize,
) -> Result<(), LosingSuffixReadErrorChirho> {
    if requested_chirho == 0 || requested_chirho > maximum_chirho {
        return Err(LosingSuffixReadErrorChirho::InvalidPageLimitChirho {
            limit_chirho,
            requested_chirho,
            maximum_chirho,
        });
    }
    Ok(())
}

fn validate_manifest_digest_chirho(digest_chirho: &str) -> Result<(), LosingSuffixReadErrorChirho> {
    if !is_blake3_hex_digest_chirho(digest_chirho) {
        return Err(LosingSuffixReadErrorChirho::InvalidIdentityFieldChirho {
            field_chirho: LosingSuffixIdentityFieldChirho::ManifestTailDigestChirho,
            observed_bytes_chirho: digest_chirho.len(),
        });
    }
    Ok(())
}

fn validate_cursor_payload_chirho(
    payload_chirho: &LosingSuffixCursorPayloadChirho,
) -> Result<(), LosingSuffixReadErrorChirho> {
    if payload_chirho.schema_chirho != LOSING_SUFFIX_CURSOR_SCHEMA_CHIRHO {
        return Err(LosingSuffixReadErrorChirho::CursorMalformedChirho {
            detail_chirho: "cursor schema is unsupported".to_owned(),
        });
    }
    if payload_chirho.key_id_chirho.is_empty() {
        return Err(LosingSuffixReadErrorChirho::CursorMalformedChirho {
            detail_chirho: "cursor key id is empty".to_owned(),
        });
    }
    validate_identity_digest_chirho(
        LosingSuffixIdentityFieldChirho::GenesisDigestChirho,
        &payload_chirho.identity_chirho.genesis_digest_chirho,
    )?;
    validate_identity_digest_chirho(
        LosingSuffixIdentityFieldChirho::FrozenTailDigestChirho,
        &payload_chirho.frozen_tail_chirho.record_digest_chirho,
    )?;
    validate_identity_digest_chirho(
        LosingSuffixIdentityFieldChirho::AnchorDigestChirho,
        &payload_chirho.exact_anchor_chirho.record_digest_chirho,
    )?;
    if !is_blake3_hex_digest_chirho(&payload_chirho.expected_digest_chirho.0)
        || payload_chirho.next_seq_chirho <= payload_chirho.exact_anchor_chirho.seq_chirho
        || payload_chirho.next_seq_chirho > payload_chirho.frozen_tail_chirho.seq_chirho
    {
        return Err(LosingSuffixReadErrorChirho::CursorContinuityMismatchChirho);
    }
    match &payload_chirho.source_chirho {
        LosingSuffixCursorSourceChirho::ActiveChirho {
            end_offset_chirho,
            predecessor_manifest_entry_digest_chirho,
        } => {
            if *end_offset_chirho == 0 {
                return Err(LosingSuffixReadErrorChirho::CursorContinuityMismatchChirho);
            }
            if let Some(digest_chirho) = predecessor_manifest_entry_digest_chirho {
                validate_manifest_digest_chirho(digest_chirho)?;
            }
        }
        LosingSuffixCursorSourceChirho::SealedChirho {
            manifest_entry_digest_chirho,
            end_offset_chirho,
        } => {
            validate_manifest_digest_chirho(manifest_entry_digest_chirho)?;
            if *end_offset_chirho == 0 {
                return Err(LosingSuffixReadErrorChirho::CursorContinuityMismatchChirho);
            }
        }
    }
    Ok(())
}

fn canonical_cursor_payload_chirho(
    payload_chirho: &LosingSuffixCursorPayloadChirho,
) -> Result<String, LosingSuffixReadErrorChirho> {
    serde_json::to_string(payload_chirho).map_err(|error_chirho| {
        LosingSuffixReadErrorChirho::CursorMalformedChirho {
            detail_chirho: error_chirho.to_string(),
        }
    })
}

fn canonical_cursor_wire_chirho(
    cursor_chirho: &LosingSuffixCursorChirho,
) -> Result<Vec<u8>, LosingSuffixReadErrorChirho> {
    let bytes_chirho = serde_json::to_vec(&LosingSuffixCursorWireChirho {
        payload_chirho: cursor_chirho.payload_chirho.clone(),
        signature_chirho: cursor_chirho.signature_chirho.clone(),
    })
    .map_err(
        |error_chirho| LosingSuffixReadErrorChirho::CursorMalformedChirho {
            detail_chirho: error_chirho.to_string(),
        },
    )?;
    if bytes_chirho.len() > MAX_LOSING_SUFFIX_CURSOR_BYTES_CHIRHO {
        return Err(LosingSuffixReadErrorChirho::CursorBytesTooLargeChirho {
            observed_chirho: bytes_chirho.len(),
            maximum_chirho: MAX_LOSING_SUFFIX_CURSOR_BYTES_CHIRHO,
        });
    }
    Ok(bytes_chirho)
}

fn storage_error_chirho(error_chirho: impl std::fmt::Display) -> LosingSuffixReadErrorChirho {
    LosingSuffixReadErrorChirho::StorageChirho {
        detail_chirho: error_chirho.to_string(),
    }
}

fn load_index_entry_chirho(
    storage_chirho: &dyn SegmentStorageChirho,
    continuity_chirho: &SegmentContinuityOverLedgerSignerPortChirho<'_>,
    paths_chirho: &SegmentPathsChirho,
    identity_digest_chirho: &str,
    digest_chirho: &str,
) -> Result<SegmentManifestEntryChirho, LosingSuffixReadErrorChirho> {
    let line_chirho = load_predecessor_index_entry_chirho(
        storage_chirho,
        continuity_chirho,
        paths_chirho,
        digest_chirho,
        identity_digest_chirho,
    )
    .map_err(
        |error_chirho| LosingSuffixReadErrorChirho::PredecessorIndexChirho {
            digest_chirho: digest_chirho.to_owned(),
            detail_chirho: format!("{error_chirho:#}"),
        },
    )?;
    Ok(line_chirho.entry_chirho)
}

fn read_window_chirho(
    storage_chirho: &dyn SegmentStorageChirho,
    path_chirho: &SegmentPathChirho,
    end_offset_chirho: u64,
    requested_bytes_chirho: usize,
) -> Result<(u64, Vec<u8>), LosingSuffixReadErrorChirho> {
    let read_len_chirho = end_offset_chirho.min(requested_bytes_chirho as u64);
    let start_offset_chirho = end_offset_chirho - read_len_chirho;
    let bytes_chirho = storage_chirho
        .read_range_chirho(path_chirho, start_offset_chirho, read_len_chirho)
        .map_err(storage_error_chirho)?;
    if bytes_chirho.last() != Some(&b'\n') {
        return Err(LosingSuffixReadErrorChirho::SegmentBoundaryMismatchChirho {
            detail_chirho: "reverse range does not end at a JSONL line boundary".to_owned(),
        });
    }
    Ok((start_offset_chirho, bytes_chirho))
}

fn first_complete_offset_chirho(
    start_offset_chirho: u64,
    bytes_chirho: &[u8],
) -> Result<usize, LosingSuffixReadErrorChirho> {
    if start_offset_chirho == 0 {
        return Ok(0);
    }
    bytes_chirho
        .iter()
        .position(|byte_chirho| *byte_chirho == b'\n')
        .map(|position_chirho| position_chirho + 1)
        .ok_or_else(
            || LosingSuffixReadErrorChirho::SegmentBoundaryMismatchChirho {
                detail_chirho: "bounded reverse range contains no complete JSONL line".to_owned(),
            },
        )
}

fn verify_rotation_clear_chirho(
    storage_chirho: &dyn SegmentStorageChirho,
    paths_chirho: &SegmentPathsChirho,
) -> Result<(), LosingSuffixReadErrorChirho> {
    if storage_chirho
        .exists_chirho(&paths_chirho.rotation_marker_chirho())
        .map_err(storage_error_chirho)?
    {
        return Err(LosingSuffixReadErrorChirho::PendingRotationChirho);
    }
    Ok(())
}

impl LedgerJournalChirho<'_> {
    fn verify_current_seal_binding_chirho(
        &self,
        storage_chirho: &dyn SegmentStorageChirho,
        continuity_chirho: &SegmentContinuityOverLedgerSignerPortChirho<'_>,
        paths_chirho: &SegmentPathsChirho,
        identity_digest_chirho: &str,
    ) -> Result<Option<SegmentManifestEntryChirho>, LosingSuffixReadErrorChirho> {
        verify_rotation_clear_chirho(storage_chirho, paths_chirho)?;
        let manifest_len_chirho = storage_chirho
            .object_len_chirho(&paths_chirho.manifest_chirho())
            .map_err(storage_error_chirho)?;
        if self.base_seq_chirho == 0 {
            if manifest_len_chirho.is_some_and(|length_chirho| length_chirho != 0)
                || self.manifest_tail_entry_digest_chirho.is_some()
            {
                return Err(LosingSuffixReadErrorChirho::SealStateMismatchChirho {
                    detail_chirho:
                        "unrotated checkpoint no longer matches the segment manifest state"
                            .to_owned(),
                });
            }
            return Ok(None);
        }
        let base_chirho = try_manifest_head_fast_path_chirho(
            storage_chirho,
            continuity_chirho,
            paths_chirho,
            identity_digest_chirho,
        )
        .map_err(storage_error_chirho)?
        .ok_or_else(|| LosingSuffixReadErrorChirho::SealStateMismatchChirho {
            detail_chirho:
                "rotated checkpoint requires an exact authenticated manifest-head checkpoint"
                    .to_owned(),
        })?;
        if base_chirho.base_seq_chirho != self.base_seq_chirho
            || base_chirho.last_entry_digest_chirho != self.manifest_tail_entry_digest_chirho
        {
            return Err(LosingSuffixReadErrorChirho::SealStateMismatchChirho {
                detail_chirho: "authenticated manifest head differs from the held checkpoint"
                    .to_owned(),
            });
        }
        let digest_chirho = self
            .manifest_tail_entry_digest_chirho
            .as_deref()
            .ok_or_else(|| LosingSuffixReadErrorChirho::SealStateMismatchChirho {
                detail_chirho: "rotated checkpoint omits its manifest-tail digest".to_owned(),
            })?;
        let entry_chirho = load_index_entry_chirho(
            storage_chirho,
            continuity_chirho,
            paths_chirho,
            identity_digest_chirho,
            digest_chirho,
        )?;
        if entry_chirho.next_first_seq_chirho != self.base_seq_chirho {
            return Err(LosingSuffixReadErrorChirho::SealStateMismatchChirho {
                detail_chirho: "authenticated predecessor index differs from the held segment base"
                    .to_owned(),
            });
        }
        Ok(Some(entry_chirho))
    }

    fn verify_current_tail_body_chirho(
        &self,
        body_chirho: &[u8],
    ) -> Result<(), LosingSuffixReadErrorChirho> {
        let text_chirho = std::str::from_utf8(body_chirho).map_err(|error_chirho| {
            LosingSuffixReadErrorChirho::RecordEncodingChirho {
                expected_seq_chirho: self.tail_seq_chirho,
                detail_chirho: error_chirho.to_string(),
            }
        })?;
        if stored_line_digest_chirho(text_chirho) != self.tail_digest_chirho {
            return Err(LosingSuffixReadErrorChirho::RecordDigestMismatchChirho {
                seq_chirho: self.tail_seq_chirho,
            });
        }
        let line_chirho =
            parse_canonical_ledger_journal_line_chirho(text_chirho).map_err(|error_chirho| {
                LosingSuffixReadErrorChirho::RecordEncodingChirho {
                    expected_seq_chirho: self.tail_seq_chirho,
                    detail_chirho: format!("{error_chirho:?}"),
                }
            })?;
        let observed_epoch_chirho = match &line_chirho {
            LedgerJournalLineChirho::GenesisChirho(genesis_chirho) => {
                if self.tail_seq_chirho != 0
                    || genesis_chirho.cluster_id_chirho != self.cluster_id_chirho
                {
                    return Err(LosingSuffixReadErrorChirho::RecordSequenceMismatchChirho {
                        expected_chirho: self.tail_seq_chirho,
                        observed_chirho: 0,
                    });
                }
                genesis_chirho.epoch_chirho
            }
            LedgerJournalLineChirho::RecordChirho(record_chirho) => {
                if record_chirho.seq_chirho != self.tail_seq_chirho {
                    return Err(LosingSuffixReadErrorChirho::RecordSequenceMismatchChirho {
                        expected_chirho: self.tail_seq_chirho,
                        observed_chirho: record_chirho.seq_chirho,
                    });
                }
                record_chirho.epoch_chirho
            }
        };
        if observed_epoch_chirho != self.last_recorded_epoch_chirho {
            return Err(LosingSuffixReadErrorChirho::TailEpochMismatchChirho {
                expected_chirho: self.last_recorded_epoch_chirho,
                observed_chirho: observed_epoch_chirho,
            });
        }
        verify_tail_signature_chirho(self.signer_chirho, &line_chirho).map_err(|_error_chirho| {
            LosingSuffixReadErrorChirho::RecordSignatureInvalidChirho {
                seq_chirho: self.tail_seq_chirho,
            }
        })
    }

    fn verify_active_current_tail_chirho(&self) -> Result<(), LosingSuffixReadErrorChirho> {
        if self.tail_line_len_chirho == 0
            || self.tail_line_len_chirho > MAX_CURRENT_LOSING_TAIL_LINE_BYTES_CHIRHO as u64
        {
            return Err(LosingSuffixReadErrorChirho::TailLineBytesTooLargeChirho {
                observed_chirho: self.tail_line_len_chirho,
                maximum_chirho: MAX_CURRENT_LOSING_TAIL_LINE_BYTES_CHIRHO,
            });
        }
        let physical_len_chirho = self.tail_line_len_chirho.checked_add(1).ok_or_else(|| {
            LosingSuffixReadErrorChirho::SegmentBoundaryMismatchChirho {
                detail_chirho: "active tail physical length overflowed".to_owned(),
            }
        })?;
        if self
            .tail_line_offset_chirho
            .checked_add(physical_len_chirho)
            != Some(self.tail_byte_len_chirho)
        {
            return Err(LosingSuffixReadErrorChirho::SegmentBoundaryMismatchChirho {
                detail_chirho: "active tail coordinates do not end at the checkpoint length"
                    .to_owned(),
            });
        }
        let physical_chirho = self
            .storage_chirho
            .read_exact_range_chirho(
                &self.path_chirho,
                self.tail_line_offset_chirho,
                physical_len_chirho,
            )
            .map_err(storage_error_chirho)?;
        if physical_chirho.last() != Some(&b'\n')
            || physical_chirho[..physical_chirho.len() - 1].contains(&b'\n')
        {
            return Err(LosingSuffixReadErrorChirho::SegmentBoundaryMismatchChirho {
                detail_chirho: "active tail is not one LF-terminated canonical line".to_owned(),
            });
        }
        self.verify_current_tail_body_chirho(&physical_chirho[..physical_chirho.len() - 1])
    }

    fn verify_sealed_current_tail_chirho(
        &self,
        storage_chirho: &dyn SegmentStorageChirho,
        paths_chirho: &SegmentPathsChirho,
        entry_chirho: &SegmentManifestEntryChirho,
    ) -> Result<(), LosingSuffixReadErrorChirho> {
        if entry_chirho.last_seq_chirho != self.tail_seq_chirho {
            return Err(LosingSuffixReadErrorChirho::RecordSequenceMismatchChirho {
                expected_chirho: self.tail_seq_chirho,
                observed_chirho: entry_chirho.last_seq_chirho,
            });
        }
        let segment_path_chirho =
            paths_chirho.sealed_segment_chirho(&entry_chirho.segment_digest_chirho);
        let observed_len_chirho = storage_chirho
            .object_len_chirho(&segment_path_chirho)
            .map_err(storage_error_chirho)?;
        if observed_len_chirho != Some(entry_chirho.byte_len_chirho) {
            return Err(LosingSuffixReadErrorChirho::SegmentLengthMismatchChirho {
                digest_chirho: entry_chirho.segment_digest_chirho.clone(),
                expected_chirho: entry_chirho.byte_len_chirho,
                observed_chirho: observed_len_chirho,
            });
        }
        let maximum_window_chirho = MAX_CURRENT_LOSING_TAIL_LINE_BYTES_CHIRHO + 2;
        let mut requested_window_chirho =
            INITIAL_REVERSE_READ_BYTES_CHIRHO.min(maximum_window_chirho);
        let (window_chirho, first_complete_chirho) = loop {
            let (start_chirho, candidate_chirho) = read_window_chirho(
                storage_chirho,
                &segment_path_chirho,
                entry_chirho.byte_len_chirho,
                requested_window_chirho,
            )?;
            let first_chirho = first_complete_offset_chirho(start_chirho, &candidate_chirho)?;
            if first_chirho < candidate_chirho.len()
                || start_chirho == 0
                || requested_window_chirho == maximum_window_chirho
            {
                break (candidate_chirho, first_chirho);
            }
            requested_window_chirho = requested_window_chirho
                .saturating_mul(2)
                .min(maximum_window_chirho);
        };
        if first_complete_chirho >= window_chirho.len() || window_chirho.last() != Some(&b'\n') {
            return Err(LosingSuffixReadErrorChirho::TailLineBytesTooLargeChirho {
                observed_chirho: maximum_window_chirho as u64,
                maximum_chirho: MAX_CURRENT_LOSING_TAIL_LINE_BYTES_CHIRHO,
            });
        }
        let body_end_chirho = window_chirho.len() - 1;
        let body_start_chirho = window_chirho[first_complete_chirho..body_end_chirho]
            .iter()
            .rposition(|byte_chirho| *byte_chirho == b'\n')
            .map(|position_chirho| first_complete_chirho + position_chirho + 1)
            .unwrap_or(first_complete_chirho);
        let body_chirho = &window_chirho[body_start_chirho..body_end_chirho];
        if body_chirho.len() > MAX_CURRENT_LOSING_TAIL_LINE_BYTES_CHIRHO {
            return Err(LosingSuffixReadErrorChirho::TailLineBytesTooLargeChirho {
                observed_chirho: body_chirho.len() as u64,
                maximum_chirho: MAX_CURRENT_LOSING_TAIL_LINE_BYTES_CHIRHO,
            });
        }
        if blake3::hash(&window_chirho[body_start_chirho..])
            .to_hex()
            .to_string()
            != entry_chirho.final_line_digest_chirho
        {
            return Err(LosingSuffixReadErrorChirho::SegmentBoundaryMismatchChirho {
                detail_chirho: "sealed tail physical-line digest mismatches its index".to_owned(),
            });
        }
        self.verify_current_tail_body_chirho(body_chirho)
    }

    /// Revalidate the current physical losing tail without scanning history or trusting a cached
    /// coordinate alone. This reads at most the exact checkpoint state, one bounded manifest-head
    /// sidecar, one authenticated predecessor-index entry, and one tail line capped at 4 MiB.
    pub fn revalidate_current_losing_tail_chirho(
        &self,
    ) -> Result<VerifiedLosingJournalTailChirho, LosingSuffixReadErrorChirho> {
        let storage_chirho = SegmentStorageOverLedgerPortChirho::new_chirho(self.storage_chirho);
        let continuity_chirho =
            SegmentContinuityOverLedgerSignerPortChirho::new_chirho(self.signer_chirho);
        let paths_chirho = SegmentPathsChirho::new_chirho(self.path_chirho.key_chirho());
        let identity_digest_chirho =
            LogIdentityChirho::new_chirho(format!("cairn-ledger:{}", self.cluster_id_chirho.0))
                .digest_chirho();
        let sealed_entry_before_chirho = self.verify_current_seal_binding_chirho(
            &storage_chirho,
            &continuity_chirho,
            &paths_chirho,
            &identity_digest_chirho,
        )?;
        let observed_active_len_chirho = storage_chirho
            .object_len_chirho(&paths_chirho.active_chirho())
            .map_err(storage_error_chirho)?;
        if observed_active_len_chirho != Some(self.tail_physical_byte_len_chirho) {
            return Err(LosingSuffixReadErrorChirho::ActiveLengthMismatchChirho {
                expected_chirho: self.tail_physical_byte_len_chirho,
                observed_chirho: observed_active_len_chirho,
            });
        }
        if self.tail_byte_len_chirho > 0 {
            self.verify_active_current_tail_chirho()?;
        } else {
            let sealed_entry_chirho = sealed_entry_before_chirho.as_ref().ok_or_else(|| {
                LosingSuffixReadErrorChirho::SealStateMismatchChirho {
                    detail_chirho:
                        "empty active journal requires an authenticated sealed predecessor"
                            .to_owned(),
                }
            })?;
            self.verify_sealed_current_tail_chirho(
                &storage_chirho,
                &paths_chirho,
                sealed_entry_chirho,
            )?;
        }
        let sealed_entry_after_chirho = self.verify_current_seal_binding_chirho(
            &storage_chirho,
            &continuity_chirho,
            &paths_chirho,
            &identity_digest_chirho,
        )?;
        if sealed_entry_before_chirho != sealed_entry_after_chirho {
            return Err(LosingSuffixReadErrorChirho::SealStateMismatchChirho {
                detail_chirho: "segment seal state changed during tail revalidation".to_owned(),
            });
        }
        let observed_active_len_after_chirho = storage_chirho
            .object_len_chirho(&paths_chirho.active_chirho())
            .map_err(storage_error_chirho)?;
        if observed_active_len_after_chirho != Some(self.tail_physical_byte_len_chirho) {
            return Err(LosingSuffixReadErrorChirho::ActiveLengthMismatchChirho {
                expected_chirho: self.tail_physical_byte_len_chirho,
                observed_chirho: observed_active_len_after_chirho,
            });
        }
        Ok(self.verified_losing_tail_chirho())
    }

    /// Decode, canonicalize, and root-verify one durable continuation.
    pub fn decode_verified_losing_suffix_cursor_chirho(
        &self,
        bytes_chirho: &[u8],
    ) -> Result<LosingSuffixCursorChirho, LosingSuffixReadErrorChirho> {
        if bytes_chirho.is_empty() || bytes_chirho.len() > MAX_LOSING_SUFFIX_CURSOR_BYTES_CHIRHO {
            return Err(LosingSuffixReadErrorChirho::CursorBytesTooLargeChirho {
                observed_chirho: bytes_chirho.len(),
                maximum_chirho: MAX_LOSING_SUFFIX_CURSOR_BYTES_CHIRHO,
            });
        }
        let wire_chirho: LosingSuffixCursorWireChirho = serde_json::from_slice(bytes_chirho)
            .map_err(
                |error_chirho| LosingSuffixReadErrorChirho::CursorMalformedChirho {
                    detail_chirho: error_chirho.to_string(),
                },
            )?;
        let cursor_chirho = LosingSuffixCursorChirho {
            payload_chirho: wire_chirho.payload_chirho,
            signature_chirho: wire_chirho.signature_chirho,
        };
        if canonical_cursor_wire_chirho(&cursor_chirho)? != bytes_chirho {
            return Err(LosingSuffixReadErrorChirho::CursorNonCanonicalChirho);
        }
        self.verify_cursor_chirho(&cursor_chirho)?;
        Ok(cursor_chirho)
    }

    fn verify_cursor_chirho(
        &self,
        cursor_chirho: &LosingSuffixCursorChirho,
    ) -> Result<(), LosingSuffixReadErrorChirho> {
        validate_cursor_payload_chirho(&cursor_chirho.payload_chirho)?;
        let payload_chirho = canonical_cursor_payload_chirho(&cursor_chirho.payload_chirho)?;
        if !self
            .signer_chirho
            .verify_chirho(&payload_chirho, &cursor_chirho.signature_chirho)
        {
            return Err(LosingSuffixReadErrorChirho::CursorSignatureInvalidChirho);
        }
        Ok(())
    }

    fn mint_cursor_chirho(
        &self,
        request_chirho: &LosingSuffixPageRequestChirho,
        next_seq_chirho: u64,
        expected_digest_chirho: DigestChirho,
        source_chirho: LosingSuffixCursorSourceChirho,
    ) -> Result<LosingSuffixCursorChirho, LosingSuffixReadErrorChirho> {
        let payload_chirho = LosingSuffixCursorPayloadChirho {
            schema_chirho: LOSING_SUFFIX_CURSOR_SCHEMA_CHIRHO.to_owned(),
            key_id_chirho: self.signer_chirho.key_id_chirho(),
            identity_chirho: request_chirho.identity_chirho.clone(),
            frozen_tail_chirho: request_chirho.frozen_tail_chirho.clone(),
            exact_anchor_chirho: request_chirho.exact_anchor_chirho.clone(),
            next_seq_chirho,
            expected_digest_chirho,
            source_chirho,
        };
        validate_cursor_payload_chirho(&payload_chirho)?;
        let signature_chirho = self
            .signer_chirho
            .sign_chirho(&canonical_cursor_payload_chirho(&payload_chirho)?)
            .map_err(storage_error_chirho)?;
        let cursor_chirho = LosingSuffixCursorChirho {
            payload_chirho,
            signature_chirho,
        };
        canonical_cursor_wire_chirho(&cursor_chirho)?;
        Ok(cursor_chirho)
    }

    fn verified_page_chirho(
        &self,
        request_chirho: &LosingSuffixPageRequestChirho,
        records_newest_first_chirho: Vec<LedgerRecordChirho>,
        encoded_record_bytes_chirho: usize,
        next_cursor_chirho: Option<LosingSuffixCursorChirho>,
        reached_anchor_chirho: bool,
    ) -> VerifiedLosingSuffixPageChirho {
        VerifiedLosingSuffixPageChirho {
            identity_chirho: request_chirho.identity_chirho.clone(),
            frozen_tail_chirho: request_chirho.frozen_tail_chirho.clone(),
            exact_anchor_chirho: request_chirho.exact_anchor_chirho.clone(),
            records_newest_first_chirho,
            encoded_record_bytes_chirho,
            next_cursor_chirho,
            reached_anchor_chirho,
        }
    }

    /// Return one bounded newest-first page without a manifest scan or storage listing.
    pub fn read_verified_losing_suffix_page_chirho(
        &self,
        request_chirho: &LosingSuffixPageRequestChirho,
    ) -> Result<VerifiedLosingSuffixPageChirho, LosingSuffixReadErrorChirho> {
        validate_request_chirho(request_chirho)?;
        if request_chirho.identity_chirho.genesis_digest_chirho != self.genesis_digest_chirho {
            return Err(LosingSuffixReadErrorChirho::JournalIdentityMismatchChirho);
        }
        if request_chirho.frozen_tail_chirho.seq_chirho != self.tail_seq_chirho
            || request_chirho.frozen_tail_chirho.record_digest_chirho != self.tail_digest_chirho
        {
            return Err(LosingSuffixReadErrorChirho::FrozenTailMismatchChirho);
        }
        if request_chirho.exact_anchor_chirho.seq_chirho
            > request_chirho.frozen_tail_chirho.seq_chirho
        {
            return Err(LosingSuffixReadErrorChirho::AnchorAfterFrozenTailChirho);
        }
        if request_chirho.exact_anchor_chirho.seq_chirho
            == request_chirho.frozen_tail_chirho.seq_chirho
        {
            if request_chirho.exact_anchor_chirho.record_digest_chirho
                != request_chirho.frozen_tail_chirho.record_digest_chirho
            {
                return Err(LosingSuffixReadErrorChirho::AnchorDigestMismatchAtFrozenTailChirho);
            }
            return Ok(self.verified_page_chirho(request_chirho, Vec::new(), 0, None, true));
        }

        let storage_chirho = SegmentStorageOverLedgerPortChirho::new_chirho(self.storage_chirho);
        let continuity_chirho =
            SegmentContinuityOverLedgerSignerPortChirho::new_chirho(self.signer_chirho);
        let paths_chirho = SegmentPathsChirho::new_chirho(self.path_chirho.key_chirho());
        let identity_digest_chirho =
            LogIdentityChirho::new_chirho(format!("cairn-ledger:{}", self.cluster_id_chirho.0))
                .digest_chirho();

        let (mut next_seq_chirho, mut expected_digest_chirho, mut source_chirho) =
            if let Some(cursor_chirho) = &request_chirho.cursor_chirho {
                self.verify_cursor_chirho(cursor_chirho)?;
                if !cursor_chirho.is_bound_to_request_chirho(request_chirho) {
                    return Err(LosingSuffixReadErrorChirho::CursorContinuityMismatchChirho);
                }
                (
                    cursor_chirho.payload_chirho.next_seq_chirho,
                    cursor_chirho.payload_chirho.expected_digest_chirho.clone(),
                    cursor_chirho.payload_chirho.source_chirho.clone(),
                )
            } else if self.tail_byte_len_chirho > 0 {
                (
                    self.tail_seq_chirho,
                    self.tail_digest_chirho.clone(),
                    LosingSuffixCursorSourceChirho::ActiveChirho {
                        end_offset_chirho: self.tail_byte_len_chirho,
                        predecessor_manifest_entry_digest_chirho: self
                            .manifest_tail_entry_digest_chirho
                            .clone(),
                    },
                )
            } else {
                let digest_chirho = self
                    .manifest_tail_entry_digest_chirho
                    .clone()
                    .ok_or(LosingSuffixReadErrorChirho::SegmentChainEndedBeforeAnchorChirho)?;
                validate_manifest_digest_chirho(&digest_chirho)?;
                let entry_chirho = load_index_entry_chirho(
                    &storage_chirho,
                    &continuity_chirho,
                    &paths_chirho,
                    &identity_digest_chirho,
                    &digest_chirho,
                )?;
                (
                    self.tail_seq_chirho,
                    self.tail_digest_chirho.clone(),
                    LosingSuffixCursorSourceChirho::SealedChirho {
                        manifest_entry_digest_chirho: digest_chirho,
                        end_offset_chirho: entry_chirho.byte_len_chirho,
                    },
                )
            };

        let mut records_chirho = Vec::with_capacity(request_chirho.max_records_chirho);
        let mut body_bytes_chirho = 0usize;
        loop {
            if next_seq_chirho == request_chirho.exact_anchor_chirho.seq_chirho {
                if expected_digest_chirho != request_chirho.exact_anchor_chirho.record_digest_chirho
                {
                    return Err(LosingSuffixReadErrorChirho::AnchorDigestMismatchChirho);
                }
                return Ok(self.verified_page_chirho(
                    request_chirho,
                    records_chirho,
                    body_bytes_chirho,
                    None,
                    true,
                ));
            }
            if records_chirho.len() == request_chirho.max_records_chirho
                || body_bytes_chirho == request_chirho.max_bytes_chirho
            {
                let cursor_chirho = self.mint_cursor_chirho(
                    request_chirho,
                    next_seq_chirho,
                    expected_digest_chirho,
                    source_chirho,
                )?;
                return Ok(self.verified_page_chirho(
                    request_chirho,
                    records_chirho,
                    body_bytes_chirho,
                    Some(cursor_chirho),
                    false,
                ));
            }

            let (path_chirho, source_end_chirho, sealed_entry_chirho, verify_final_line_chirho) =
                match &source_chirho {
                    LosingSuffixCursorSourceChirho::ActiveChirho {
                        end_offset_chirho,
                        predecessor_manifest_entry_digest_chirho,
                    } => {
                        if predecessor_manifest_entry_digest_chirho
                            != &self.manifest_tail_entry_digest_chirho
                        {
                            return Err(
                                LosingSuffixReadErrorChirho::CursorContinuityMismatchChirho,
                            );
                        }
                        let observed_chirho = storage_chirho
                            .object_len_chirho(&paths_chirho.active_chirho())
                            .map_err(storage_error_chirho)?;
                        if observed_chirho != Some(self.tail_physical_byte_len_chirho)
                            || *end_offset_chirho > self.tail_byte_len_chirho
                            || next_seq_chirho < self.base_seq_chirho
                        {
                            return Err(LosingSuffixReadErrorChirho::ActiveLengthMismatchChirho {
                                expected_chirho: self.tail_physical_byte_len_chirho,
                                observed_chirho,
                            });
                        }
                        (
                            paths_chirho.active_chirho(),
                            *end_offset_chirho,
                            None,
                            false,
                        )
                    }
                    LosingSuffixCursorSourceChirho::SealedChirho {
                        manifest_entry_digest_chirho,
                        end_offset_chirho,
                    } => {
                        let entry_chirho = load_index_entry_chirho(
                            &storage_chirho,
                            &continuity_chirho,
                            &paths_chirho,
                            &identity_digest_chirho,
                            manifest_entry_digest_chirho,
                        )?;
                        if !is_blake3_hex_digest_chirho(&entry_chirho.segment_digest_chirho)
                            || !is_blake3_hex_digest_chirho(&entry_chirho.final_line_digest_chirho)
                        {
                            return Err(
                            LosingSuffixReadErrorChirho::SegmentBoundaryMismatchChirho {
                                detail_chirho:
                                    "authenticated segment entry contains a non-canonical digest"
                                        .to_owned(),
                            },
                        );
                        }
                        let path_chirho =
                            paths_chirho.sealed_segment_chirho(&entry_chirho.segment_digest_chirho);
                        let observed_chirho = storage_chirho
                            .object_len_chirho(&path_chirho)
                            .map_err(storage_error_chirho)?;
                        if observed_chirho != Some(entry_chirho.byte_len_chirho)
                            || *end_offset_chirho > entry_chirho.byte_len_chirho
                        {
                            return Err(LosingSuffixReadErrorChirho::SegmentLengthMismatchChirho {
                                digest_chirho: entry_chirho.segment_digest_chirho,
                                expected_chirho: entry_chirho.byte_len_chirho,
                                observed_chirho,
                            });
                        }
                        if next_seq_chirho < entry_chirho.first_seq_chirho
                            || next_seq_chirho > entry_chirho.last_seq_chirho
                            || (*end_offset_chirho == entry_chirho.byte_len_chirho
                                && next_seq_chirho != entry_chirho.last_seq_chirho)
                        {
                            return Err(
                                LosingSuffixReadErrorChirho::SegmentBoundaryMismatchChirho {
                                    detail_chirho:
                                        "cursor sequence is outside its authenticated segment"
                                            .to_owned(),
                                },
                            );
                        }
                        (
                            path_chirho,
                            *end_offset_chirho,
                            Some(entry_chirho.clone()),
                            *end_offset_chirho == entry_chirho.byte_len_chirho,
                        )
                    }
                };

            let remaining_records_chirho = request_chirho.max_records_chirho - records_chirho.len();
            let remaining_bytes_chirho = request_chirho.max_bytes_chirho - body_bytes_chirho;
            let max_window_bytes_chirho = remaining_bytes_chirho
                .saturating_add(remaining_records_chirho)
                .saturating_add(1)
                .min(
                    MAX_LOSING_SUFFIX_PAGE_BYTES_CHIRHO + MAX_LOSING_SUFFIX_PAGE_RECORDS_CHIRHO + 1,
                );
            let mut requested_window_bytes_chirho =
                INITIAL_REVERSE_READ_BYTES_CHIRHO.min(max_window_bytes_chirho);
            let (read_start_chirho, window_chirho, first_complete_chirho) = loop {
                let (candidate_start_chirho, candidate_window_chirho) = read_window_chirho(
                    &storage_chirho,
                    &path_chirho,
                    source_end_chirho,
                    requested_window_bytes_chirho,
                )?;
                let candidate_first_chirho =
                    first_complete_offset_chirho(candidate_start_chirho, &candidate_window_chirho)?;
                if candidate_first_chirho < candidate_window_chirho.len()
                    || candidate_start_chirho == 0
                    || requested_window_bytes_chirho == max_window_bytes_chirho
                {
                    break (
                        candidate_start_chirho,
                        candidate_window_chirho,
                        candidate_first_chirho,
                    );
                }
                requested_window_bytes_chirho = requested_window_bytes_chirho
                    .saturating_mul(2)
                    .min(max_window_bytes_chirho);
            };
            let mut local_end_chirho = window_chirho.len();
            let records_before_chirho = records_chirho.len();
            let mut first_line_chirho = true;
            while local_end_chirho > first_complete_chirho
                && records_chirho.len() < request_chirho.max_records_chirho
            {
                let body_end_chirho = local_end_chirho - 1;
                let body_start_chirho = window_chirho[first_complete_chirho..body_end_chirho]
                    .iter()
                    .rposition(|byte_chirho| *byte_chirho == b'\n')
                    .map(|position_chirho| first_complete_chirho + position_chirho + 1)
                    .unwrap_or(first_complete_chirho);
                let body_chirho = &window_chirho[body_start_chirho..body_end_chirho];
                if body_chirho.len() > request_chirho.max_bytes_chirho - body_bytes_chirho {
                    if records_chirho.is_empty() {
                        return Err(LosingSuffixReadErrorChirho::RecordExceedsPageBytesChirho {
                            seq_chirho: next_seq_chirho,
                            maximum_chirho: request_chirho.max_bytes_chirho,
                        });
                    }
                    break;
                }
                if verify_final_line_chirho && first_line_chirho {
                    let physical_digest_chirho =
                        blake3::hash(&window_chirho[body_start_chirho..local_end_chirho])
                            .to_hex()
                            .to_string();
                    if sealed_entry_chirho.as_ref().is_none_or(|entry_chirho| {
                        entry_chirho.final_line_digest_chirho != physical_digest_chirho
                    }) {
                        return Err(LosingSuffixReadErrorChirho::SegmentBoundaryMismatchChirho {
                            detail_chirho: "sealed segment final physical line digest mismatches"
                                .to_owned(),
                        });
                    }
                }
                first_line_chirho = false;
                let body_text_chirho =
                    std::str::from_utf8(body_chirho).map_err(|error_chirho| {
                        LosingSuffixReadErrorChirho::RecordEncodingChirho {
                            expected_seq_chirho: next_seq_chirho,
                            detail_chirho: error_chirho.to_string(),
                        }
                    })?;
                let record_chirho = match parse_canonical_ledger_journal_line_chirho(
                    body_text_chirho,
                )
                .map_err(|error_chirho| {
                    LosingSuffixReadErrorChirho::RecordEncodingChirho {
                        expected_seq_chirho: next_seq_chirho,
                        detail_chirho: format!("{error_chirho:?}"),
                    }
                })? {
                    LedgerJournalLineChirho::RecordChirho(record_chirho) => record_chirho,
                    LedgerJournalLineChirho::GenesisChirho(_) => {
                        return Err(LosingSuffixReadErrorChirho::SegmentBoundaryMismatchChirho {
                            detail_chirho: "reverse suffix reached genesis before its anchor"
                                .to_owned(),
                        });
                    }
                };
                if record_chirho.seq_chirho != next_seq_chirho {
                    return Err(LosingSuffixReadErrorChirho::RecordSequenceMismatchChirho {
                        expected_chirho: next_seq_chirho,
                        observed_chirho: record_chirho.seq_chirho,
                    });
                }
                if stored_line_digest_chirho(body_text_chirho) != expected_digest_chirho {
                    return Err(LosingSuffixReadErrorChirho::RecordDigestMismatchChirho {
                        seq_chirho: next_seq_chirho,
                    });
                }
                let signed_content_chirho =
                    ledger_record_signed_content_line_chirho(&record_chirho).map_err(
                        |error_chirho| LosingSuffixReadErrorChirho::RecordEncodingChirho {
                            expected_seq_chirho: next_seq_chirho,
                            detail_chirho: format!("{error_chirho:?}"),
                        },
                    )?;
                if !self
                    .signer_chirho
                    .verify_chirho(&signed_content_chirho, &record_chirho.sig_chirho)
                {
                    return Err(LosingSuffixReadErrorChirho::RecordSignatureInvalidChirho {
                        seq_chirho: next_seq_chirho,
                    });
                }
                body_bytes_chirho += body_chirho.len();
                expected_digest_chirho = record_chirho.prev_chirho.clone();
                next_seq_chirho = next_seq_chirho
                    .checked_sub(1)
                    .ok_or(LosingSuffixReadErrorChirho::SegmentChainEndedBeforeAnchorChirho)?;
                let next_end_chirho = read_start_chirho + body_start_chirho as u64;
                match &mut source_chirho {
                    LosingSuffixCursorSourceChirho::ActiveChirho {
                        end_offset_chirho, ..
                    }
                    | LosingSuffixCursorSourceChirho::SealedChirho {
                        end_offset_chirho, ..
                    } => *end_offset_chirho = next_end_chirho,
                }
                records_chirho.push(record_chirho);
                local_end_chirho = body_start_chirho;
                if next_seq_chirho == request_chirho.exact_anchor_chirho.seq_chirho {
                    break;
                }
            }

            if next_seq_chirho == request_chirho.exact_anchor_chirho.seq_chirho {
                continue;
            }
            let source_exhausted_chirho = match &source_chirho {
                LosingSuffixCursorSourceChirho::ActiveChirho {
                    end_offset_chirho, ..
                }
                | LosingSuffixCursorSourceChirho::SealedChirho {
                    end_offset_chirho, ..
                } => *end_offset_chirho == 0,
            };
            if source_exhausted_chirho {
                let predecessor_digest_chirho = match (&source_chirho, &sealed_entry_chirho) {
                    (
                        LosingSuffixCursorSourceChirho::ActiveChirho {
                            predecessor_manifest_entry_digest_chirho,
                            ..
                        },
                        _,
                    ) => predecessor_manifest_entry_digest_chirho.clone(),
                    (LosingSuffixCursorSourceChirho::SealedChirho { .. }, Some(entry_chirho)) => {
                        entry_chirho.prev_entry_digest_chirho.clone()
                    }
                    _ => None,
                }
                .ok_or(LosingSuffixReadErrorChirho::SegmentChainEndedBeforeAnchorChirho)?;
                let predecessor_chirho = load_index_entry_chirho(
                    &storage_chirho,
                    &continuity_chirho,
                    &paths_chirho,
                    &identity_digest_chirho,
                    &predecessor_digest_chirho,
                )?;
                if let Some(current_chirho) = &sealed_entry_chirho {
                    if predecessor_chirho.generation_chirho.checked_add(1)
                        != Some(current_chirho.generation_chirho)
                        || predecessor_chirho.next_first_seq_chirho
                            != current_chirho.first_seq_chirho
                    {
                        return Err(LosingSuffixReadErrorChirho::SegmentBoundaryMismatchChirho {
                            detail_chirho: "authenticated predecessor segment is not contiguous"
                                .to_owned(),
                        });
                    }
                } else if predecessor_chirho.next_first_seq_chirho != self.base_seq_chirho {
                    return Err(LosingSuffixReadErrorChirho::SegmentBoundaryMismatchChirho {
                        detail_chirho: "active base does not follow its authenticated predecessor"
                            .to_owned(),
                    });
                }
                if predecessor_chirho.last_seq_chirho != next_seq_chirho {
                    return Err(LosingSuffixReadErrorChirho::SegmentBoundaryMismatchChirho {
                        detail_chirho: "predecessor sequence does not match the reverse chain"
                            .to_owned(),
                    });
                }
                source_chirho = LosingSuffixCursorSourceChirho::SealedChirho {
                    manifest_entry_digest_chirho: predecessor_digest_chirho,
                    end_offset_chirho: predecessor_chirho.byte_len_chirho,
                };
            }
            if records_chirho.len() == request_chirho.max_records_chirho
                || body_bytes_chirho == request_chirho.max_bytes_chirho
                || records_chirho.len() == records_before_chirho
            {
                if records_chirho.is_empty() {
                    return Err(LosingSuffixReadErrorChirho::RecordExceedsPageBytesChirho {
                        seq_chirho: next_seq_chirho,
                        maximum_chirho: request_chirho.max_bytes_chirho,
                    });
                }
                let cursor_chirho = self.mint_cursor_chirho(
                    request_chirho,
                    next_seq_chirho,
                    expected_digest_chirho,
                    source_chirho,
                )?;
                return Ok(self.verified_page_chirho(
                    request_chirho,
                    records_chirho,
                    body_bytes_chirho,
                    Some(cursor_chirho),
                    false,
                ));
            }
        }
    }
}
