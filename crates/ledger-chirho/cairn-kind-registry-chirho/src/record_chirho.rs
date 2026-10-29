// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The kind-registry record types: configuration AUTHORITY for money law (claude2 #4866 ruling a).
//! No legs, no supply, no fence — but the full chain core: dense seq + prev-digest binding + two
//! signatures per record (the ISSUER's, so per-kind extracts verify independently; and the
//! REGISTRY's injected trust root). The policy body is IMMUTABLE — its content digest IS the
//! `AssetKindRefChirho` money legs name (R5b); an amend appends a NEW body with a NEW ref and
//! supersedes the old one PROSPECTIVELY only.

use cairn_ledger_model_chirho::asset_op_chirho::RoundingChirho;
use cairn_ledger_model_chirho::ids_chirho::{AssetKindIdChirho, DigestChirho};
use serde::{Deserialize, Serialize};

/// Schema tag on every registry line — cross-domain signature confusion dies at parse.
pub const KIND_REGISTRY_SCHEMA_V1_CHIRHO: &str = "cairn-kind-registry-record-v1-chirho";

/// The chain anchor for record 0 (a thin log has no genesis record type): the domain-separated
/// digest of the registry identity, so two registries can never splice each other's chains.
pub const KIND_REGISTRY_CHAIN_DOMAIN_CHIRHO: &str = "cairn-kind-registry-chain-v1-chirho";

/// Who may mint a kind — the WIRE mirror of the admission view's `MintAuthorityPolicyChirho`
/// (the registry owns its wire stability; the projection maps record → view).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum MintAuthorityRecordChirho {
    #[serde(rename = "provider-receipt-chirho")]
    ProviderReceiptChirho,
    #[serde(rename = "platform-policy-chirho")]
    PlatformPolicyChirho { max_supply_chirho: Option<u64> },
    #[serde(rename = "closed-chirho")]
    ClosedChirho,
}

/// The CF3 W-law for idempotency retention. The idempotency horizon must dominate the full
/// retry/finality horizon so a legitimately late retry cannot outlive its deduplication evidence.
/// Both fields live in one policy object because changing either changes the same safety proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdempotencyWindowPolicyChirho {
    pub idempotency_horizon_ms_chirho: u64,
    pub retry_finality_horizon_ms_chirho: u64,
}

/// One IMMUTABLE policy body. Its canonical-bytes blake3 digest IS the kind-policy ref money legs
/// carry forever (R5b): the ref never changes meaning, only its CURRENCY (superseded or not).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KindPolicyBodyChirho {
    pub unit_chirho: String,
    pub precision_chirho: u32,
    pub mint_authority_chirho: MintAuthorityRecordChirho,
    pub rounding_chirho: RoundingChirho,
    /// The placement coordinate for this kind's account-logs shard — CARRIED and projected now,
    /// consumed by the later placement work (claude2 #4866 ruling 4).
    pub shard_attachment_chirho: String,
    /// The OWNER principal of this kind's designated SETTLEMENT account (CF2 sub-ruling a,
    /// #4931): EscrowFinalize's paired Credit leg must target LogId(this owner, this kind),
    /// resolved from the CURRENT policy — a settlement retarget via Amend is prospective by
    /// construction. None = no settlement configured = Finalize REFUSES fail-closed for this
    /// kind. Option keeps pre-CF2 registry bytes canonical (skip-if-None).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settlement_owner_chirho: Option<String>,
    /// CF3's bounded-idempotency W-law. `None` is the conservative legacy posture: keys remain
    /// unpruned until CF6 regenesis. `Some` applies prospectively to new effect intents. Keeping
    /// this optional and last preserves every pre-CF3 policy byte and content ref exactly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_window_chirho: Option<IdempotencyWindowPolicyChirho>,
}

/// What a registry record does.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum KindRegistryOpChirho {
    /// Register a NEW kind with its first policy body.
    #[serde(rename = "register-kind-chirho")]
    RegisterKindChirho {
        kind_id_chirho: AssetKindIdChirho,
        policy_chirho: KindPolicyBodyChirho,
    },
    /// Append a NEW policy body for an existing kind, superseding the named ref PROSPECTIVELY:
    /// new admissions must use the new ref; replay/history verification is untouched (structural,
    /// R5b); existing supply is never clawed back (a cap below current supply refuses further
    /// mints, fail-closed — value destruction without a burn is not a thing).
    #[serde(rename = "amend-kind-policy-chirho")]
    AmendKindPolicyChirho {
        kind_id_chirho: AssetKindIdChirho,
        supersedes_ref_chirho: cairn_ledger_model_chirho::ids_chirho::AssetKindRefChirho,
        policy_chirho: KindPolicyBodyChirho,
    },
}

/// One signed registry record (a single JSONL line on the wire).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KindRegistryRecordChirho {
    pub schema_chirho: String,
    /// Dense chain law: record N carries seq == N (0-based) and prev == the stored-line digest of
    /// record N-1 (record 0's prev == the domain-separated identity anchor).
    pub seq_chirho: u64,
    pub prev_chirho: DigestChirho,
    /// The registry log's identity (for example, `cairn-kind-registry:<cluster>`) — bound into every
    /// record so lines can never be replayed under another registry.
    pub registry_id_chirho: String,
    pub op_chirho: KindRegistryOpChirho,
    /// The issuer principal AUTHORIZING this registration/amendment.
    pub issuer_chirho: String,
    /// The issuer's signature over the signed content (sig fields emptied) — per-kind extracts
    /// verify independently on this signature (claude2 #4866 pin b).
    pub issuer_sig_chirho: String,
    /// The registry trust root's signature over the signed content INCLUDING the issuer sig
    /// (sign-then-attach; the verifying key is INJECTED, never selected by `key_id_chirho`).
    pub registry_sig_chirho: String,
    /// Informational only — NEVER consulted to select a verifying key.
    pub key_id_chirho: String,
}
