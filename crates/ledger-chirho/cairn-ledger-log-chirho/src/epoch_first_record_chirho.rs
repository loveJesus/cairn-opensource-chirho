// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Bounded evidence for the exact signed first record committed after an epoch advance.
//!
//! Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/cf8-gd7-deposed-fork-reconciliation-design-chirho.md`.

use crate::ports_chirho::LedgerSignerPortChirho;
use cairn_ledger_model_chirho::ids_chirho::DigestChirho;
use cairn_ledger_model_chirho::record_chirho::LedgerRecordChirho;
use cairn_ledger_model_chirho::wire_chirho::{
    canonical_ledger_record_line_chirho, ledger_record_signed_content_line_chirho,
    parse_canonical_ledger_journal_line_chirho, stored_line_digest_chirho, LedgerJournalLineChirho,
};
use cairn_ledger_model_chirho::ShardEpochChirho;

/// Maximum canonical bytes retained for one newly committed epoch-first record.
///
/// New append requests are separately bounded at 64 KiB. This larger constant includes derived
/// post-state fields, signatures, canonical JSON framing, and the cross-zone anchor without
/// depending on total journal history.
pub const MAX_EPOCH_FIRST_RECORD_EVIDENCE_BYTES_CHIRHO: usize = 256 * 1024;

/// Exact canonical signed record bytes emitted only when an append crosses into a new epoch.
///
/// The payload is intentionally absent for steady-state appends and for reconstructed historical
/// receipt-window entries. A durable indexer can retry these bytes after a post-commit sidecar
/// failure without rescanning the journal or reconstructing a signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochFirstRecordEvidenceChirho {
    epoch_chirho: ShardEpochChirho,
    seq_chirho: u64,
    record_digest_chirho: DigestChirho,
    canonical_record_line_chirho: String,
}

impl EpochFirstRecordEvidenceChirho {
    /// Construct verified evidence from one bounded canonical signed record line.
    ///
    /// This is used by exact-tail crash recovery and authenticated offline backfill; callers never
    /// supply the coordinate or digest independently.
    pub fn from_canonical_record_line_chirho(
        canonical_record_line_chirho: String,
        signer_chirho: &dyn LedgerSignerPortChirho,
    ) -> Result<Self, EpochFirstRecordEvidenceErrorChirho> {
        if canonical_record_line_chirho.len() > MAX_EPOCH_FIRST_RECORD_EVIDENCE_BYTES_CHIRHO {
            return Err(EpochFirstRecordEvidenceErrorChirho::BytesTooLargeChirho {
                observed_chirho: canonical_record_line_chirho.len(),
                maximum_chirho: MAX_EPOCH_FIRST_RECORD_EVIDENCE_BYTES_CHIRHO,
            });
        }
        let parsed_chirho =
            parse_canonical_ledger_journal_line_chirho(&canonical_record_line_chirho).map_err(
                |error_chirho| EpochFirstRecordEvidenceErrorChirho::WireChirho {
                    detail_chirho: format!("{error_chirho:?}"),
                },
            )?;
        let LedgerJournalLineChirho::RecordChirho(record_chirho) = parsed_chirho else {
            return Err(EpochFirstRecordEvidenceErrorChirho::NotRecordChirho);
        };
        let canonical_chirho =
            canonical_ledger_record_line_chirho(&record_chirho).map_err(|error_chirho| {
                EpochFirstRecordEvidenceErrorChirho::WireChirho {
                    detail_chirho: format!("{error_chirho:?}"),
                }
            })?;
        if canonical_chirho != canonical_record_line_chirho {
            return Err(EpochFirstRecordEvidenceErrorChirho::NonCanonicalChirho);
        }
        let record_digest_chirho = stored_line_digest_chirho(&canonical_record_line_chirho);
        let evidence_chirho = Self::from_committed_record_chirho(
            &record_chirho,
            canonical_record_line_chirho,
            record_digest_chirho,
        )?;
        evidence_chirho.verify_chirho(signer_chirho)?;
        Ok(evidence_chirho)
    }

    pub(crate) fn from_committed_record_chirho(
        record_chirho: &LedgerRecordChirho,
        canonical_record_line_chirho: String,
        record_digest_chirho: DigestChirho,
    ) -> Result<Self, EpochFirstRecordEvidenceErrorChirho> {
        if record_chirho.anchor_chirho.is_none() {
            return Err(EpochFirstRecordEvidenceErrorChirho::AnchorMissingChirho);
        }
        if canonical_record_line_chirho.len() > MAX_EPOCH_FIRST_RECORD_EVIDENCE_BYTES_CHIRHO {
            return Err(EpochFirstRecordEvidenceErrorChirho::BytesTooLargeChirho {
                observed_chirho: canonical_record_line_chirho.len(),
                maximum_chirho: MAX_EPOCH_FIRST_RECORD_EVIDENCE_BYTES_CHIRHO,
            });
        }
        if stored_line_digest_chirho(&canonical_record_line_chirho) != record_digest_chirho {
            return Err(EpochFirstRecordEvidenceErrorChirho::DigestMismatchChirho);
        }
        Ok(Self {
            epoch_chirho: record_chirho.epoch_chirho,
            seq_chirho: record_chirho.seq_chirho,
            record_digest_chirho,
            canonical_record_line_chirho,
        })
    }

    pub fn epoch_chirho(&self) -> ShardEpochChirho {
        self.epoch_chirho
    }

    pub fn seq_chirho(&self) -> u64 {
        self.seq_chirho
    }

    pub fn record_digest_chirho(&self) -> &DigestChirho {
        &self.record_digest_chirho
    }

    pub fn canonical_record_line_chirho(&self) -> &str {
        &self.canonical_record_line_chirho
    }

    /// Reparse and verify the retained canonical bytes against the injected journal trust root.
    pub fn verify_chirho(
        &self,
        signer_chirho: &dyn LedgerSignerPortChirho,
    ) -> Result<LedgerRecordChirho, EpochFirstRecordEvidenceErrorChirho> {
        if self.canonical_record_line_chirho.len() > MAX_EPOCH_FIRST_RECORD_EVIDENCE_BYTES_CHIRHO {
            return Err(EpochFirstRecordEvidenceErrorChirho::BytesTooLargeChirho {
                observed_chirho: self.canonical_record_line_chirho.len(),
                maximum_chirho: MAX_EPOCH_FIRST_RECORD_EVIDENCE_BYTES_CHIRHO,
            });
        }
        if stored_line_digest_chirho(&self.canonical_record_line_chirho)
            != self.record_digest_chirho
        {
            return Err(EpochFirstRecordEvidenceErrorChirho::DigestMismatchChirho);
        }
        let parsed_chirho =
            parse_canonical_ledger_journal_line_chirho(&self.canonical_record_line_chirho)
                .map_err(
                    |error_chirho| EpochFirstRecordEvidenceErrorChirho::WireChirho {
                        detail_chirho: format!("{error_chirho:?}"),
                    },
                )?;
        let LedgerJournalLineChirho::RecordChirho(record_chirho) = parsed_chirho else {
            return Err(EpochFirstRecordEvidenceErrorChirho::NotRecordChirho);
        };
        let canonical_chirho =
            canonical_ledger_record_line_chirho(&record_chirho).map_err(|error_chirho| {
                EpochFirstRecordEvidenceErrorChirho::WireChirho {
                    detail_chirho: format!("{error_chirho:?}"),
                }
            })?;
        if canonical_chirho != self.canonical_record_line_chirho {
            return Err(EpochFirstRecordEvidenceErrorChirho::NonCanonicalChirho);
        }
        if record_chirho.epoch_chirho != self.epoch_chirho
            || record_chirho.seq_chirho != self.seq_chirho
        {
            return Err(EpochFirstRecordEvidenceErrorChirho::CoordinateMismatchChirho);
        }
        if record_chirho.anchor_chirho.is_none() {
            return Err(EpochFirstRecordEvidenceErrorChirho::AnchorMissingChirho);
        }
        let signed_content_chirho = ledger_record_signed_content_line_chirho(&record_chirho)
            .map_err(
                |error_chirho| EpochFirstRecordEvidenceErrorChirho::WireChirho {
                    detail_chirho: format!("{error_chirho:?}"),
                },
            )?;
        if !signer_chirho.verify_chirho(&signed_content_chirho, &record_chirho.sig_chirho) {
            return Err(EpochFirstRecordEvidenceErrorChirho::SignatureInvalidChirho);
        }
        Ok(record_chirho)
    }
}

pub(crate) fn maybe_epoch_first_record_evidence_chirho(
    record_chirho: &LedgerRecordChirho,
    canonical_record_line_chirho: &str,
    record_digest_chirho: &DigestChirho,
) -> Result<Option<EpochFirstRecordEvidenceChirho>, EpochFirstRecordEvidenceErrorChirho> {
    record_chirho
        .anchor_chirho
        .as_ref()
        .map(|_anchor_chirho| {
            EpochFirstRecordEvidenceChirho::from_committed_record_chirho(
                record_chirho,
                canonical_record_line_chirho.to_owned(),
                record_digest_chirho.clone(),
            )
        })
        .transpose()
}

/// Why epoch-first evidence could not be constructed or trusted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EpochFirstRecordEvidenceErrorChirho {
    BytesTooLargeChirho {
        observed_chirho: usize,
        maximum_chirho: usize,
    },
    DigestMismatchChirho,
    WireChirho {
        detail_chirho: String,
    },
    NotRecordChirho,
    NonCanonicalChirho,
    CoordinateMismatchChirho,
    AnchorMissingChirho,
    SignatureInvalidChirho,
}
