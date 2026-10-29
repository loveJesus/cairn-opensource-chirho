// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! B-2 slice 2.3a: the ADVISORY durable head-checkpoint sidecar (§11.4 = the RC4 head-checkpoint
//! pattern): a separate, atomically-written object that remembers WHERE each account's last signed
//! leg lives (byte locators) plus the covered journal cut — so a reopen verifies the cut with two
//! range-reads and replays only the suffix (O(checkpoint state + delta), independent of total
//! history), and a passivated account rehydrates by range-reading its named SIGNED line (RC4-R2:
//! the index says WHERE to read, never WHAT the balance is on faith). STRICTLY ADVISORY: a torn /
//! stale / missing / foreign / oversized sidecar is DISCARDED (full rebuild), never an error and
//! never authority.

use cairn_ledger_model_chirho::ids_chirho::{
    AccountIdChirho, AssetKindIdChirho, AssetKindRefChirho, DigestChirho,
};
use cairn_ledger_model_chirho::record_chirho::{HlcChirho, LegPostStateChirho};
use cairn_ledger_model_chirho::ShardEpochChirho;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// The sidecar's schema-first tag.
pub const HEAD_CHECKPOINT_SCHEMA_V1_CHIRHO: &str = "ledger-head-checkpoint-v1-chirho";

/// Hard allocation ceiling for one advisory head checkpoint.
///
/// A checkpoint beyond this fixed trust-boundary cap is ignored and the journal takes its verified
/// full-open fallback. This is a safety ceiling, not a scale target: placement and state sharding
/// must keep production checkpoints substantially below it.
pub const MAX_HEAD_CHECKPOINT_BYTES_CHIRHO: usize = 8 * 1024 * 1024;

/// WHERE an account's last-touching signed leg lives, plus the post it carries. The POST rides
/// along as the working copy, but a money decision after rehydration re-verifies it against the
/// range-read SIGNED line the locator names (RC4-R2) — the locator is never balance authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeadLocatorChirho {
    pub seq_chirho: u64,
    /// Index of the LAST leg touching this account within that record.
    pub leg_index_chirho: u32,
    /// Byte offset of the record's canonical BODY within the journal object.
    pub line_offset_chirho: u64,
    /// Byte length of the canonical BODY (excludes the JSONL LF, §11.4).
    pub line_len_chirho: u64,
    /// The stored-line digest of that body — rehydration verifies the range-read bytes against it.
    pub line_digest_chirho: DigestChirho,
    pub post_chirho: LegPostStateChirho,
}

/// One (account, locator) row — a Vec entry rather than a map key because the account id is a
/// STRUCT (owner, kind_id), which JSON cannot key a map by. Rows are emitted in BTreeMap order
/// (sorted by account), so the encoding is deterministic.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeadLocatorEntryChirho {
    pub account_chirho: AccountIdChirho,
    pub locator_chirho: HeadLocatorChirho,
}

/// Rebuildable coordinates for the terminal half of one CF3 effect receipt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectTerminalReceiptCoordinatesChirho {
    pub seq_chirho: u64,
    pub hlc_chirho: HlcChirho,
    pub stored_record_digest_chirho: DigestChirho,
}

/// Rebuildable coordinates for one CF3 effect receipt. No policy horizon is copied here: replay
/// reconstructs these coordinates from signed journal records, while live pruning resolves the
/// recorded refs through the current monotone registry retention view. The original Hold
/// coordinates remain stable for the full receipt window; terminalization adds a second optional
/// coordinate instead of overwriting them, so same-K retries reconstruct both receipts exactly.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectReceiptWindowEntryChirho {
    pub intent_ref_chirho: DigestChirho,
    /// Compensation Holds use their deterministic one-per-original coordinate as escrow control.
    /// Forward intents omit this field, preserving every pre-compensation checkpoint byte.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_saga_id_chirho: Option<DigestChirho>,
    /// Present only after the one terminal record commits. Omitted while the Hold is unresolved,
    /// preserving every pre-terminal checkpoint byte and signature.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_outcome_ref_chirho: Option<DigestChirho>,
    /// The terminal record's coordinates. Omitted until terminalization, preserving every
    /// unresolved receipt checkpoint byte and signature.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_receipt_chirho: Option<EffectTerminalReceiptCoordinatesChirho>,
    /// The original Hold receipt. These coordinates never change after the intent transition.
    pub committed_seq_chirho: u64,
    pub committed_hlc_chirho: HlcChirho,
    pub stored_record_digest_chirho: DigestChirho,
    pub policy_refs_chirho: Vec<AssetKindRefChirho>,
}

impl EffectReceiptWindowEntryChirho {
    pub(crate) fn effective_control_saga_id_chirho(&self) -> &DigestChirho {
        self.control_saga_id_chirho
            .as_ref()
            .unwrap_or(&self.intent_ref_chirho)
    }
}

/// The advisory checkpoint: the covered journal cut + per-account locators + the rebuildable
/// aggregates at that cut. Everything here is a PROJECTION of the journal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeadCheckpointChirho {
    pub schema_chirho: String,
    /// Binds the sidecar to ONE journal instance — a foreign sidecar is discarded.
    pub genesis_digest_chirho: DigestChirho,
    /// Byte length of the genesis line BODY (locates line 0 for the binding check).
    pub genesis_line_len_chirho: u64,
    /// Bytes of the journal this checkpoint covers, INCLUDING each line's LF (§11.4).
    pub covered_byte_len_chirho: u64,
    /// The covered tail line's BODY locator + digest (the cut-authenticity check).
    pub covered_tail_offset_chirho: u64,
    pub covered_tail_len_chirho: u64,
    pub covered_tail_digest_chirho: DigestChirho,
    pub covered_seq_chirho: u64,
    pub covered_epoch_chirho: ShardEpochChirho,
    pub covered_hlc_chirho: HlcChirho,
    /// ROTATED-JOURNAL binding (base > 0): the segment base this checkpoint was taken at, and the
    /// VERIFIED manifest tail-entry digest at that moment. `None` on a never-rotated journal, and
    /// skip-if-None keeps legacy sidecar bytes AND signatures byte-identical. At base > 0 the fast
    /// open requires BOTH to equal the freshly-derived seal state — the pair replaces the
    /// genesis-line binding there (the manifest head is R2-verified and identity-bound, so it
    /// binds the sidecar to THIS log's seal history).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_seq_chirho: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_tail_entry_digest_chirho: Option<String>,
    pub head_locators_chirho: Vec<HeadLocatorEntryChirho>,
    /// The UNCONSUMED escrow holds at the covered cut (CF2): exact-triple key -> held amount.
    /// Empty = omitted, keeping every pre-CF2 sidecar byte and signature identical.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub active_holds_chirho: Vec<(crate::admission_chirho::EscrowHoldKeyChirho, u64)>,
    /// The CONSUMED counterpart nullifiers at the covered cut (F3a). Empty = omitted — every
    /// pre-F3a sidecar byte and signature stays identical.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub consumed_nullifiers_chirho:
        Vec<cairn_ledger_model_chirho::counterpart_chirho::CounterpartNullifierChirho>,
    pub supply_by_kind_chirho: BTreeMap<AssetKindIdChirho, u64>,
    pub idempotency_window_chirho: BTreeSet<String>,
    /// Bounded CF3 receipts are separate from the legacy-unpruned key set. Empty = omitted, so a
    /// pre-CF3 checkpoint's canonical bytes and signature remain byte-identical.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub effect_receipt_window_chirho: BTreeMap<String, EffectReceiptWindowEntryChirho>,
    /// Trust-root signature over the sidecar's SIGNED CONTENT (this record with `sig` empty). The
    /// sidecar carries AGGREGATE balances the fast open would otherwise trust on faith — signing it
    /// makes those aggregates trust-root-vouched, so a Byzantine tamper of the sidecar (fabricated
    /// balances) breaks this sig and the fast open discards to the full rebuild. Staleness (an
    /// old signed sidecar) is handled by the O(delta) suffix replay, not by the sig.
    pub sig_chirho: String,
}

impl HeadCheckpointChirho {
    /// The sidecar's sign-message bytes: this checkpoint with `sig` EMPTIED, canonicalized (the
    /// sign-then-attach idiom, mirroring the record). `None` on a wrong schema tag.
    pub fn signing_message_chirho(&self) -> Option<Vec<u8>> {
        let mut unsigned_chirho = self.clone();
        unsigned_chirho.sig_chirho = String::new();
        canonical_head_checkpoint_bytes_chirho(&unsigned_chirho)
    }
}

/// Why a sidecar was DISCARDED (advisory: every one of these means "full rebuild", never an error).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CheckpointDiscardChirho {
    MissingChirho,
    MalformedChirho,
    WrongSchemaChirho,
    ForeignJournalChirho,
    AheadOfJournalChirho,
    CutUnverifiedChirho,
}

/// Strict parse of sidecar bytes: typed deserialize + schema check + exact reserialize-byte
/// equality (defensive J0a — the sidecar is advisory, but a normalized-parse divergence should
/// discard, not half-trust).
pub fn parse_head_checkpoint_chirho(
    bytes_chirho: &[u8],
) -> Result<HeadCheckpointChirho, CheckpointDiscardChirho> {
    let text_chirho =
        std::str::from_utf8(bytes_chirho).map_err(|_| CheckpointDiscardChirho::MalformedChirho)?;
    let checkpoint_chirho: HeadCheckpointChirho =
        serde_json::from_str(text_chirho).map_err(|_| CheckpointDiscardChirho::MalformedChirho)?;
    if checkpoint_chirho.schema_chirho != HEAD_CHECKPOINT_SCHEMA_V1_CHIRHO {
        return Err(CheckpointDiscardChirho::WrongSchemaChirho);
    }
    let reserialized_chirho = serde_json::to_string(&checkpoint_chirho)
        .map_err(|_| CheckpointDiscardChirho::MalformedChirho)?;
    if reserialized_chirho != text_chirho {
        return Err(CheckpointDiscardChirho::MalformedChirho);
    }
    Ok(checkpoint_chirho)
}

/// Canonical sidecar bytes (compact serde-JSON; fail-closed on a wrong in-memory schema tag).
pub fn canonical_head_checkpoint_bytes_chirho(
    checkpoint_chirho: &HeadCheckpointChirho,
) -> Option<Vec<u8>> {
    if checkpoint_chirho.schema_chirho != HEAD_CHECKPOINT_SCHEMA_V1_CHIRHO {
        return None;
    }
    serde_json::to_string(checkpoint_chirho)
        .ok()
        .map(String::into_bytes)
}
