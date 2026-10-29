// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Typed open, recovery, storage, and tail-verification contract for the journal engine.

use super::{AppendReceiptChirho, AppendRequestBoundDimensionChirho};
use crate::admission_chirho::AdmissionRejectChirho;
use crate::ports_chirho::LedgerSignerPortChirho;
use cairn_ledger_model_chirho::ids_chirho::DigestChirho;
use cairn_ledger_model_chirho::wire_chirho::{
    ledger_genesis_signed_content_line_chirho, ledger_record_signed_content_line_chirho,
    LedgerJournalLineChirho, WireErrorChirho,
};

/// Why the journal engine refused — typed and fail-closed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JournalErrorChirho {
    StorageChirho {
        detail_chirho: String,
    },
    SignerChirho {
        detail_chirho: String,
    },
    WireChirho {
        error_chirho: WireErrorChirho,
    },
    /// A new append request exceeded policy before lookup, cloning, folding, signing, or storage.
    AppendRequestBoundsChirho {
        dimension_chirho: AppendRequestBoundDimensionChirho,
        observed_at_least_chirho: usize,
        maximum_chirho: usize,
    },
    AppendRequestPreflightChirho {
        detail_chirho: String,
    },
    MirrorReconciliationRefusedChirho {
        detail_chirho: String,
    },
    MirrorPrepareRefusedChirho {
        detail_chirho: String,
    },
    /// The local journal append committed, but remote durable receipt finalization is still pending.
    MirrorCommittedEvidencePendingChirho {
        receipt_chirho: Box<AppendReceiptChirho>,
        detail_chirho: String,
    },
    ChainChirho {
        detail_chirho: String,
    },
    TornTailChirho,
    ReadOnlyRecoveryRequiredChirho {
        reason_chirho: ReadOnlyRecoveryReasonChirho,
    },
    ReadOnlyExactCheckpointRequiredChirho,
    ReadOnlyExactCheckpointTailRefusedChirho {
        detail_chirho: String,
    },
    TailSignatureInvalidChirho,
    AdmissionChirho {
        reject_chirho: AdmissionRejectChirho,
    },
    EffectIntentChirho {
        detail_chirho: String,
    },
    EffectTerminalChirho {
        detail_chirho: String,
    },
    EffectTerminalConflictChirho {
        key_chirho: String,
        existing_outcome_ref_chirho: DigestChirho,
        attempted_outcome_ref_chirho: DigestChirho,
    },
    StaleIntentChirho {
        key_chirho: String,
        age_ms_chirho: u64,
        idempotency_horizon_ms_chirho: u64,
    },
    StaleEffectTerminalChirho {
        intent_ref_chirho: DigestChirho,
        age_ms_chirho: u64,
        retry_finality_horizon_ms_chirho: u64,
    },
}

/// The exact repair authority a read-only journal open refused to exercise.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadOnlyRecoveryReasonChirho {
    PendingRotationChirho,
    TornTailChirho,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum JournalOpenPostureChirho {
    RepairingChirho,
    ReadOnlyChirho,
}

impl From<AdmissionRejectChirho> for JournalErrorChirho {
    fn from(reject_chirho: AdmissionRejectChirho) -> Self {
        JournalErrorChirho::AdmissionChirho { reject_chirho }
    }
}

impl From<WireErrorChirho> for JournalErrorChirho {
    fn from(error_chirho: WireErrorChirho) -> Self {
        JournalErrorChirho::WireChirho { error_chirho }
    }
}

pub(crate) fn storage_error_chirho(error_chirho: anyhow::Error) -> JournalErrorChirho {
    JournalErrorChirho::StorageChirho {
        detail_chirho: error_chirho.to_string(),
    }
}

/// Verify the successor-less tail against the injected trust root. Full open replays every line,
/// so an earlier mutation ripples through `prev` to this signature. Fast open trusts signed covered
/// aggregates and detects an interior covered-byte mutation at the next full open, not here.
pub(crate) fn verify_tail_signature_chirho(
    signer_chirho: &dyn LedgerSignerPortChirho,
    tail_line_chirho: &LedgerJournalLineChirho,
) -> Result<(), JournalErrorChirho> {
    let (signed_content_chirho, sig_chirho) = match tail_line_chirho {
        LedgerJournalLineChirho::GenesisChirho(genesis_chirho) => (
            ledger_genesis_signed_content_line_chirho(genesis_chirho)?,
            &genesis_chirho.sig_chirho,
        ),
        LedgerJournalLineChirho::RecordChirho(record_chirho) => (
            ledger_record_signed_content_line_chirho(record_chirho)?,
            &record_chirho.sig_chirho,
        ),
    };
    if signer_chirho.verify_chirho(&signed_content_chirho, sig_chirho) {
        Ok(())
    } else {
        Err(JournalErrorChirho::TailSignatureInvalidChirho)
    }
}
