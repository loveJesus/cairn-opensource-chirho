// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Exact-tail recovery for a committed epoch-first record whose sidecar write did not finish.

use super::{storage_error_chirho, JournalErrorChirho, LedgerJournalChirho};
use crate::epoch_first_record_chirho::{
    maybe_epoch_first_record_evidence_chirho, EpochFirstRecordEvidenceChirho,
    MAX_EPOCH_FIRST_RECORD_EVIDENCE_BYTES_CHIRHO,
};
use cairn_ledger_model_chirho::ids_chirho::DigestChirho;
use cairn_ledger_model_chirho::record_chirho::LedgerRecordChirho;
use cairn_ledger_model_chirho::wire_chirho::{
    parse_canonical_ledger_journal_line_chirho, stored_line_digest_chirho, LedgerJournalLineChirho,
};

pub(super) fn prepare_epoch_first_record_evidence_chirho(
    record_chirho: &LedgerRecordChirho,
    canonical_record_line_chirho: &str,
    record_digest_chirho: &DigestChirho,
) -> Result<Option<EpochFirstRecordEvidenceChirho>, JournalErrorChirho> {
    maybe_epoch_first_record_evidence_chirho(
        record_chirho,
        canonical_record_line_chirho,
        record_digest_chirho,
    )
    .map_err(
        |error_chirho| JournalErrorChirho::AppendRequestPreflightChirho {
            detail_chirho: format!(
                "epoch-first record evidence refused before storage: {error_chirho:?}"
            ),
        },
    )
}

impl LedgerJournalChirho<'_> {
    /// Recover bounded epoch-first evidence only when that record is still the exact verified tail.
    ///
    /// This closes the append-committed/sidecar-not-written crash window without scanning history.
    /// `None` means the tail is genesis or a steady-state record. A caller that also lacks the
    /// term-first index must stay held and use a separate authenticated offline backfill.
    pub fn tail_epoch_first_record_evidence_chirho(
        &self,
    ) -> Result<Option<EpochFirstRecordEvidenceChirho>, JournalErrorChirho> {
        if self.tail_seq_chirho == 0 {
            return Ok(None);
        }
        if self.tail_line_len_chirho > MAX_EPOCH_FIRST_RECORD_EVIDENCE_BYTES_CHIRHO as u64 {
            return Err(JournalErrorChirho::ChainChirho {
                detail_chirho: "epoch-first tail evidence exceeds the fixed online recovery bound"
                    .to_owned(),
            });
        }
        let object_len_chirho = self
            .storage_chirho
            .object_len_chirho(&self.path_chirho)
            .map_err(storage_error_chirho)?
            .ok_or_else(|| JournalErrorChirho::ChainChirho {
                detail_chirho: "journal disappeared during epoch-first tail recovery".to_owned(),
            })?;
        let tail_end_chirho = self
            .tail_line_offset_chirho
            .checked_add(self.tail_line_len_chirho)
            .ok_or_else(|| JournalErrorChirho::ChainChirho {
                detail_chirho: "epoch-first tail locator overflowed".to_owned(),
            })?;
        if tail_end_chirho > object_len_chirho {
            return Err(JournalErrorChirho::ChainChirho {
                detail_chirho: "epoch-first tail locator exceeds the active journal".to_owned(),
            });
        }
        let tail_bytes_chirho = self
            .storage_chirho
            .read_exact_range_chirho(
                &self.path_chirho,
                self.tail_line_offset_chirho,
                self.tail_line_len_chirho,
            )
            .map_err(storage_error_chirho)?;
        let tail_line_chirho =
            String::from_utf8(tail_bytes_chirho).map_err(|_| JournalErrorChirho::ChainChirho {
                detail_chirho: "epoch-first tail is not canonical UTF-8".to_owned(),
            })?;
        if stored_line_digest_chirho(&tail_line_chirho) != self.tail_digest_chirho {
            return Err(JournalErrorChirho::ChainChirho {
                detail_chirho: "epoch-first tail digest differs from the verified journal cut"
                    .to_owned(),
            });
        }
        let parsed_chirho = parse_canonical_ledger_journal_line_chirho(&tail_line_chirho)?;
        let LedgerJournalLineChirho::RecordChirho(record_chirho) = parsed_chirho else {
            return Err(JournalErrorChirho::ChainChirho {
                detail_chirho: "non-record tail followed a nonzero journal sequence".to_owned(),
            });
        };
        if record_chirho.seq_chirho != self.tail_seq_chirho {
            return Err(JournalErrorChirho::ChainChirho {
                detail_chirho: "epoch-first tail sequence differs from the verified journal cut"
                    .to_owned(),
            });
        }
        let evidence_chirho = maybe_epoch_first_record_evidence_chirho(
            &record_chirho,
            &tail_line_chirho,
            &self.tail_digest_chirho,
        )
        .map_err(|error_chirho| JournalErrorChirho::ChainChirho {
            detail_chirho: format!("epoch-first tail evidence is invalid: {error_chirho:?}"),
        })?;
        if let Some(evidence_chirho) = &evidence_chirho {
            evidence_chirho
                .verify_chirho(self.signer_chirho)
                .map_err(|error_chirho| JournalErrorChirho::ChainChirho {
                    detail_chirho: format!(
                        "epoch-first tail signature evidence is invalid: {error_chirho:?}"
                    ),
                })?;
        }
        Ok(evidence_chirho)
    }
}
