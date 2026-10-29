// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The saga record family: what the coordinator's own append-only log is made of — a DISTINCT
//! schema tag (saga ≠ journal ≠ registry, #4901 b-i), canonical wire with the exact-reserialize
//! law, and root sign-then-attach. Journal receipts ride inside records as EVIDENCE only (b-ii).

use anyhow::{bail, Context, Result};
use cairn_ledger_model_chirho::ids_chirho::{AssetKindRefChirho, ClusterIdChirho, DigestChirho};
use cairn_ledger_model_chirho::record_chirho::HlcChirho;
use serde::{Deserialize, Serialize};

/// The saga family's schema tag — every router refuses cross-domain lines on this alone.
pub const SAGA_RECORD_SCHEMA_V1_CHIRHO: &str = "ledger-saga-record-v1-chirho";
/// The saga family's chain-core domain (the anchor's domain separation).
pub const SAGA_CHAIN_DOMAIN_CHIRHO: &str = "ledger-saga-chain-v1-chirho";

/// One planned escrow step: which journal, whose account, which kind revision, how much, and the
/// settlement account the finalize leg will credit. The settlement owner is CARRIED, not trusted —
/// the journal's admission refuses it unless it equals the kind policy's designated owner.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SagaStepPlanChirho {
    pub cluster_chirho: ClusterIdChirho,
    pub owner_chirho: String,
    pub kind_chirho: String,
    pub kind_policy_ref_chirho: AssetKindRefChirho,
    pub amount_chirho: u64,
    pub settlement_owner_chirho: String,
}

/// HOW a step's journal effect is evidenced in the saga log. A live receipt embeds the journal's
/// append coordinates; a resumed observation records that the coordinator re-learned the effect
/// from the journal's own admission laws after a crash (DuplicateEscrowHold ⇒ held;
/// UnknownEscrowHold post-decision ⇒ consumed). Both are EVIDENCE about a journal — never
/// authority; a consumer re-verifies against the journal it names.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum SagaStepEvidenceChirho {
    #[serde(rename = "receipt-chirho")]
    ReceiptChirho {
        seq_chirho: u64,
        record_digest_chirho: DigestChirho,
        hlc_chirho: HlcChirho,
    },
    #[serde(rename = "resumed-observation-chirho")]
    ResumedObservationChirho,
}

/// Why the saga decided to abort.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum SagaAbortReasonChirho {
    #[serde(rename = "hold-refused-chirho")]
    HoldRefusedChirho { detail_chirho: String },
    #[serde(rename = "ttl-expired-chirho")]
    TtlExpiredChirho,
    #[serde(rename = "operator-chirho")]
    OperatorChirho { detail_chirho: String },
}

/// The saga's phase-2 decision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum SagaDecisionChirho {
    #[serde(rename = "finalize-chirho")]
    FinalizeChirho,
    #[serde(rename = "abort-chirho")]
    AbortChirho {
        reason_chirho: SagaAbortReasonChirho,
    },
}

/// A closed saga's outcome.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum SagaOutcomeChirho {
    #[serde(rename = "finalized-chirho")]
    FinalizedChirho,
    #[serde(rename = "compensated-chirho")]
    CompensatedChirho,
}

/// One saga log operation. INTENT is durable BEFORE the first journal append (the resume law's
/// ground); every later op names a step or the decision. The TTL deadline rides the intent — the
/// durable timer record (#4901 d).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum SagaOpChirho {
    #[serde(rename = "intent-chirho")]
    IntentChirho {
        token_chirho: String,
        steps_chirho: Vec<SagaStepPlanChirho>,
        opened_at_ms_chirho: u64,
        ttl_ms_chirho: u64,
    },
    #[serde(rename = "step-held-chirho")]
    StepHeldChirho {
        step_chirho: u32,
        evidence_chirho: SagaStepEvidenceChirho,
    },
    #[serde(rename = "decision-chirho")]
    DecisionChirho { decision_chirho: SagaDecisionChirho },
    #[serde(rename = "step-settled-chirho")]
    StepSettledChirho {
        step_chirho: u32,
        evidence_chirho: SagaStepEvidenceChirho,
    },
    #[serde(rename = "step-released-chirho")]
    StepReleasedChirho {
        step_chirho: u32,
        evidence_chirho: SagaStepEvidenceChirho,
    },
    #[serde(rename = "closed-chirho")]
    ClosedChirho { outcome_chirho: SagaOutcomeChirho },
}

/// One signed saga log record: chain fields + the multiplexing saga id + the op, root-signed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SagaRecordChirho {
    pub schema_chirho: String,
    pub seq_chirho: u64,
    pub prev_chirho: String,
    /// The saga LOG's identity (the chain anchor's instance id) — the cross-log identity net.
    pub saga_log_id_chirho: String,
    /// Which saga this op belongs to (one log carries many sagas).
    pub saga_id_chirho: DigestChirho,
    pub op_chirho: SagaOpChirho,
    pub root_sig_chirho: String,
}

/// The saga id is DERIVED (never caller-stated): the domain-separated digest of the log identity
/// plus the caller's idempotency token — so a crash-resumed coordinator re-derives the same id.
pub fn derive_saga_id_chirho(saga_log_id_chirho: &str, token_chirho: &str) -> DigestChirho {
    let mut hasher_chirho = blake3::Hasher::new();
    hasher_chirho.update(SAGA_CHAIN_DOMAIN_CHIRHO.as_bytes());
    hasher_chirho.update(b":");
    hasher_chirho.update(saga_log_id_chirho.as_bytes());
    hasher_chirho.update(b":");
    hasher_chirho.update(token_chirho.as_bytes());
    DigestChirho(hasher_chirho.finalize().to_hex().to_string())
}

/// Canonical line: validate then the ONE serde emission.
pub fn canonical_saga_line_chirho(record_chirho: &SagaRecordChirho) -> Result<String> {
    if record_chirho.schema_chirho != SAGA_RECORD_SCHEMA_V1_CHIRHO {
        bail!("unsupported saga record schema");
    }
    if record_chirho.saga_log_id_chirho.is_empty() {
        bail!("saga record must name its log");
    }
    if let SagaOpChirho::IntentChirho { steps_chirho, .. } = &record_chirho.op_chirho {
        if steps_chirho.is_empty() {
            bail!("saga intent must plan at least one step");
        }
    }
    serde_json::to_string(record_chirho).context("encode canonical saga record")
}

/// Strict parse: schema probe, typed decode, exact reserialize-byte equality.
pub fn parse_canonical_saga_line_chirho(line_chirho: &str) -> Result<SagaRecordChirho> {
    #[derive(Deserialize)]
    struct SchemaProbeChirho {
        schema_chirho: String,
    }
    let probe_chirho: SchemaProbeChirho =
        serde_json::from_str(line_chirho).context("probe saga record schema")?;
    if probe_chirho.schema_chirho != SAGA_RECORD_SCHEMA_V1_CHIRHO {
        bail!("unsupported saga record schema");
    }
    let record_chirho: SagaRecordChirho =
        serde_json::from_str(line_chirho).context("decode saga record")?;
    let canonical_chirho = canonical_saga_line_chirho(&record_chirho)?;
    if canonical_chirho != line_chirho {
        bail!("saga record has a byte-canonical mismatch");
    }
    Ok(record_chirho)
}

/// The root-signed content: the canonical line with the signature blanked (sign-then-attach).
pub fn saga_root_signed_content_chirho(record_chirho: &SagaRecordChirho) -> Result<String> {
    let mut unsigned_chirho = record_chirho.clone();
    unsigned_chirho.root_sig_chirho = String::new();
    canonical_saga_line_chirho(&unsigned_chirho)
}
