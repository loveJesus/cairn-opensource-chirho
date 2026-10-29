// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Journal-owned, transport-neutral F1 mirror port for the ledger append boundary.
//!
//! The port sees exactly one fully admitted, signed, canonical ledger line. It never receives an
//! append request, signer, storage path, effect provider, or writer handle. PREPARE must complete
//! before the local durable append; FINALIZE may fail only as committed evidence pending.

use cairn_ledger_model_chirho::ids_chirho::{ClusterIdChirho, DigestChirho};
use cairn_ledger_model_chirho::record_chirho::HlcChirho;
use cairn_ledger_model_chirho::ShardEpochChirho;

const LEDGER_APPEND_CALLER_KEY_DIGEST_DOMAIN_V1_CHIRHO: &[u8] =
    b"cairn-ledger-append-caller-key-v1-chirho";

/// The current verified local tail supplied before every new append attempt.
///
/// A mirror adapter uses this cut to reconcile a prior PREPARE/commit/FINALIZE interruption before
/// the journal evaluates duplicate admission. Fields are private so only the verified journal can
/// construct the value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerAppendMirrorTailChirho {
    cluster_id_chirho: ClusterIdChirho,
    journal_genesis_digest_chirho: DigestChirho,
    tail_seq_chirho: u64,
    tail_record_digest_chirho: DigestChirho,
    tail_hlc_chirho: HlcChirho,
    tail_record_epoch_chirho: ShardEpochChirho,
    current_epoch_chirho: ShardEpochChirho,
}

impl LedgerAppendMirrorTailChirho {
    pub(crate) fn new_chirho(
        cluster_id_chirho: ClusterIdChirho,
        journal_genesis_digest_chirho: DigestChirho,
        tail_seq_chirho: u64,
        tail_record_digest_chirho: DigestChirho,
        tail_hlc_chirho: HlcChirho,
        tail_record_epoch_chirho: ShardEpochChirho,
        current_epoch_chirho: ShardEpochChirho,
    ) -> Self {
        Self {
            cluster_id_chirho,
            journal_genesis_digest_chirho,
            tail_seq_chirho,
            tail_record_digest_chirho,
            tail_hlc_chirho,
            tail_record_epoch_chirho,
            current_epoch_chirho,
        }
    }

    pub fn cluster_id_chirho(&self) -> &ClusterIdChirho {
        &self.cluster_id_chirho
    }

    pub fn journal_genesis_digest_chirho(&self) -> &DigestChirho {
        &self.journal_genesis_digest_chirho
    }

    pub fn tail_seq_chirho(&self) -> u64 {
        self.tail_seq_chirho
    }

    pub fn tail_record_digest_chirho(&self) -> &DigestChirho {
        &self.tail_record_digest_chirho
    }

    pub fn tail_hlc_chirho(&self) -> &HlcChirho {
        &self.tail_hlc_chirho
    }

    /// Epoch carried by the tail record itself.
    ///
    /// This can lag `current_epoch_chirho` after an election advances the writer fence but before
    /// that term appends its first record. Mirror evidence binds the record coordinate, never the
    /// prospective append epoch.
    pub fn tail_record_epoch_chirho(&self) -> ShardEpochChirho {
        self.tail_record_epoch_chirho
    }

    pub fn current_epoch_chirho(&self) -> ShardEpochChirho {
        self.current_epoch_chirho
    }
}

impl crate::journal_chirho::LedgerJournalChirho<'_> {
    /// Opaque exact tail for mirror bootstrap/recovery. Only a verified open journal can mint it.
    pub fn verified_append_mirror_tail_chirho(&self) -> LedgerAppendMirrorTailChirho {
        LedgerAppendMirrorTailChirho::new_chirho(
            self.cluster_id_chirho.clone(),
            self.genesis_digest_chirho.clone(),
            self.tail_seq_chirho,
            self.tail_digest_chirho.clone(),
            self.tail_hlc_chirho.clone(),
            self.last_recorded_epoch_chirho,
            self.current_epoch_chirho,
        )
    }
}

/// One exact F1 ledger member after signing and full admission but before local durable append.
///
/// The canonical line already carries the journal signature. The protocol-level caller binding is
/// a domain-separated digest; the canonical line still contains its normal bounded ledger fields.
/// No HTTP request body or arbitrary request-copy object crosses this port.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerAppendMirrorCandidateChirho {
    cluster_id_chirho: ClusterIdChirho,
    journal_genesis_digest_chirho: DigestChirho,
    predecessor_seq_chirho: u64,
    predecessor_digest_chirho: DigestChirho,
    record_seq_chirho: u64,
    record_digest_chirho: DigestChirho,
    record_epoch_chirho: ShardEpochChirho,
    record_hlc_chirho: HlcChirho,
    caller_idempotency_key_digest_chirho: String,
    canonical_record_line_chirho: String,
}

pub(crate) struct LedgerAppendMirrorCandidateInputChirho {
    pub cluster_id_chirho: ClusterIdChirho,
    pub journal_genesis_digest_chirho: DigestChirho,
    pub predecessor_seq_chirho: u64,
    pub predecessor_digest_chirho: DigestChirho,
    pub record_seq_chirho: u64,
    pub record_digest_chirho: DigestChirho,
    pub record_epoch_chirho: ShardEpochChirho,
    pub record_hlc_chirho: HlcChirho,
    pub caller_idempotency_key_chirho: String,
    pub canonical_record_line_chirho: String,
}

impl LedgerAppendMirrorCandidateChirho {
    pub(crate) fn new_chirho(input_chirho: LedgerAppendMirrorCandidateInputChirho) -> Self {
        let mut caller_hasher_chirho = blake3::Hasher::new();
        caller_hasher_chirho.update(LEDGER_APPEND_CALLER_KEY_DIGEST_DOMAIN_V1_CHIRHO);
        caller_hasher_chirho
            .update(&(input_chirho.caller_idempotency_key_chirho.len() as u64).to_le_bytes());
        caller_hasher_chirho.update(input_chirho.caller_idempotency_key_chirho.as_bytes());
        Self {
            cluster_id_chirho: input_chirho.cluster_id_chirho,
            journal_genesis_digest_chirho: input_chirho.journal_genesis_digest_chirho,
            predecessor_seq_chirho: input_chirho.predecessor_seq_chirho,
            predecessor_digest_chirho: input_chirho.predecessor_digest_chirho,
            record_seq_chirho: input_chirho.record_seq_chirho,
            record_digest_chirho: input_chirho.record_digest_chirho,
            record_epoch_chirho: input_chirho.record_epoch_chirho,
            record_hlc_chirho: input_chirho.record_hlc_chirho,
            caller_idempotency_key_digest_chirho: caller_hasher_chirho
                .finalize()
                .to_hex()
                .to_string(),
            canonical_record_line_chirho: input_chirho.canonical_record_line_chirho,
        }
    }

    pub fn cluster_id_chirho(&self) -> &ClusterIdChirho {
        &self.cluster_id_chirho
    }

    pub fn journal_genesis_digest_chirho(&self) -> &DigestChirho {
        &self.journal_genesis_digest_chirho
    }

    pub fn predecessor_seq_chirho(&self) -> u64 {
        self.predecessor_seq_chirho
    }

    pub fn predecessor_digest_chirho(&self) -> &DigestChirho {
        &self.predecessor_digest_chirho
    }

    pub fn record_seq_chirho(&self) -> u64 {
        self.record_seq_chirho
    }

    pub fn record_digest_chirho(&self) -> &DigestChirho {
        &self.record_digest_chirho
    }

    pub fn record_epoch_chirho(&self) -> ShardEpochChirho {
        self.record_epoch_chirho
    }

    pub fn record_hlc_chirho(&self) -> &HlcChirho {
        &self.record_hlc_chirho
    }

    pub fn caller_idempotency_key_digest_chirho(&self) -> &str {
        &self.caller_idempotency_key_digest_chirho
    }

    pub fn canonical_record_line_chirho(&self) -> &str {
        &self.canonical_record_line_chirho
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerAppendMirrorPortErrorChirho {
    detail_chirho: String,
}

impl LedgerAppendMirrorPortErrorChirho {
    pub fn new_chirho(detail_chirho: impl Into<String>) -> Self {
        Self {
            detail_chirho: detail_chirho.into(),
        }
    }

    pub fn detail_chirho(&self) -> &str {
        &self.detail_chirho
    }
}

impl std::fmt::Display for LedgerAppendMirrorPortErrorChirho {
    fn fmt(&self, formatter_chirho: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter_chirho.write_str(&self.detail_chirho)
    }
}

impl std::error::Error for LedgerAppendMirrorPortErrorChirho {}

/// F1 mirror boundary. Implementors may hold transport/storage state, but no method grants ledger
/// authority. A successful PREPARE is required before local commit; a failed FINALIZE means the
/// local append committed and its receipt must remain visible as evidence-pending.
pub trait LedgerAppendMirrorPortChirho: Send + Sync {
    /// Refuse a tenant-migration source fence while mirror-before-ACK still carries an unresolved
    /// leader intent. The resident actor calls this inside its serialized command loop immediately
    /// before the durable fence, so a later target cannot inherit an old-view pending record that
    /// it has no authority to finalize or clear.
    fn require_no_unreconciled_pending_append_chirho(
        &self,
    ) -> Result<(), LedgerAppendMirrorPortErrorChirho>;

    fn reconcile_before_append_chirho(
        &self,
        local_tail_chirho: &LedgerAppendMirrorTailChirho,
    ) -> Result<(), LedgerAppendMirrorPortErrorChirho>;

    fn prepare_append_chirho(
        &self,
        candidate_chirho: &LedgerAppendMirrorCandidateChirho,
    ) -> Result<(), LedgerAppendMirrorPortErrorChirho>;

    fn finalize_append_chirho(
        &self,
        committed_candidate_chirho: &LedgerAppendMirrorCandidateChirho,
    ) -> Result<(), LedgerAppendMirrorPortErrorChirho>;
}
