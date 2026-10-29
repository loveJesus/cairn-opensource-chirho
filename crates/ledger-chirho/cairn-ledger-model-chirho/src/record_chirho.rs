// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The real signed ledger record — the frozen §11 two-leg per-cluster-journal shape (Brick 2.1). Pure
//! DTOs, zero I/O. Option fields pin the canonical serialization (None → ABSENT, never `null`) so the
//! J0a byte-law (F5) can reject a malleated re-encode.

use crate::counterpart_chirho::CounterpartClaimChirho;
use crate::ids_chirho::{AccountIdChirho, AssetKindRefChirho, DigestChirho};
use crate::ShardEpochChirho;
use serde::{Deserialize, Serialize};

/// A per-journal hybrid logical clock (frozen §11.1, CF0 P3): physical ms + a logical tiebreaker.
/// `Ord` derives lexicographic `(physical_ms, logical)` — the per-journal monotonicity law compares
/// with exactly this order (field declaration order is load-bearing).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HlcChirho {
    pub physical_ms_chirho: u64,
    pub logical_chirho: u32,
}

/// An account's OWN running totals AFTER a leg (Pr1: the signed leg IS that account's balance
/// authority). Spendable (F4) = `credits_total − debits_total − held ≥ 0`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegPostStateChirho {
    pub credits_total_chirho: u64,
    pub debits_total_chirho: u64,
    pub held_chirho: u64,
}

/// The effect of a leg on its account (frozen §11.2). Externally tagged (schema-tagged), never
/// serde-untagged (J0b harvest law). Wire discriminants are pinned bare-kebab with explicit
/// `serde(rename)` (the op-binding precedent) so a Rust rename can never silently fork the wire (A3).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LegDeltaChirho {
    #[serde(rename = "credit")]
    CreditChirho,
    #[serde(rename = "debit")]
    DebitChirho,
    #[serde(rename = "hold")]
    HoldChirho,
    #[serde(rename = "release")]
    ReleaseChirho,
    #[serde(rename = "finalize")]
    FinalizeChirho,
}

/// One leg = one account touched by the record (frozen §11.2). A balanced record's legs satisfy
/// ΣΔ = 0 PER STABLE KIND (R5a — keyed by `account.kind_id`, never by the policy digest).
/// `counterpart` is `Some` ONLY on a cross-cluster boundary credit leg (F3).
///
/// Kind-identity binding law (R5b): `kind_policy_ref` is the immutable policy REVISION the leg was
/// admitted under; the account's STABLE kind is `account.kind_id`. Admission (B) enforces
/// `resolve(kind_policy_ref).kind_id == account.kind_id` via the registry — the reference
/// grammar/arithmetic oracle never resolves policy, it keys conservation by the stable id.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerLegChirho {
    pub account_chirho: AccountIdChirho,
    pub kind_policy_ref_chirho: AssetKindRefChirho,
    pub delta_chirho: LegDeltaChirho,
    pub amount_chirho: u64,
    pub post_chirho: LegPostStateChirho,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counterpart_chirho: Option<CounterpartClaimChirho>,
}

/// The R4 typed CONTROL IDENTITY every escrow op carries (CF2 revision, both seats
/// #4930/#4931): a Release/Finalize must name the EXACT unconsumed hold it consumes — the
/// (account, saga, step) triple is the uniqueness key, so an unordered Release can never free a
/// hold its saga still relies on and two sagas can never race one hold.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EscrowControlChirho {
    pub saga_id_chirho: DigestChirho,
    pub step_chirho: u32,
}

/// The record-level operation tag (frozen §11.6). Externally tagged (schema-tagged); unknown-field
/// rejection comes from the J0a byte-law (A3), never serde-untagged (J0b harvest law). Wire
/// discriminants pinned bare-kebab (A3); inner FIELDS keep their `*_chirho` snake names.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LedgerOpChirho {
    /// A balanced 2-leg (or fee-bearing 3+-leg) transfer within one cluster.
    #[serde(rename = "transfer")]
    TransferChirho,
    #[serde(rename = "credit")]
    CreditChirho,
    #[serde(rename = "debit")]
    DebitChirho,
    #[serde(rename = "escrow-hold")]
    EscrowHoldChirho { control_chirho: EscrowControlChirho },
    #[serde(rename = "escrow-finalize")]
    EscrowFinalizeChirho { control_chirho: EscrowControlChirho },
    #[serde(rename = "escrow-release")]
    EscrowReleaseChirho { control_chirho: EscrowControlChirho },
    #[serde(rename = "compensation")]
    CompensationChirho { of_chirho: DigestChirho },
    #[serde(rename = "mint")]
    MintChirho {
        authority_evidence_chirho: DigestChirho,
    },
    #[serde(rename = "burn")]
    BurnChirho {
        authority_evidence_chirho: DigestChirho,
    },
    #[serde(rename = "timer")]
    TimerChirho {
        fires_at_hlc_chirho: HlcChirho,
        purpose_chirho: String,
    },
}

/// Who a record (and its compensation billing) is attributed to (frozen §11.1). Wire discriminants
/// pinned bare-kebab (A3).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AttributionChirho {
    #[serde(rename = "causer")]
    CauserChirho { principal_chirho: String },
    #[serde(rename = "platform")]
    PlatformChirho,
    #[serde(rename = "policy")]
    PolicyChirho { policy_ref_chirho: DigestChirho },
}

/// Domain separator so an attribution digest can never collide with another blake3 use.
const ATTRIBUTION_BINDING_DOMAIN_CHIRHO: &str = "cairn-ledger-attribution-binding-v1-chirho";

impl AttributionChirho {
    /// A domain-separated digest that BINDS an attribution without carrying it.
    ///
    /// `CauserChirho::principal_chirho` is an unvalidated `String` and can hold identifying free
    /// text. Anywhere a consumer only needs to prove "this attribution equals that one" — the GD7
    /// record-law check is exactly that — this digest preserves the equality while publishing no
    /// principal. Fields are LENGTH-PREFIX framed and the variant is framed as its own field, so a
    /// principal containing the variant tag cannot collide with a different variant
    /// (`framing_chirho`, the A1 money-audit finding).
    pub fn binding_digest_chirho(&self) -> String {
        let mut hasher_chirho = blake3::Hasher::new();
        crate::framing_chirho::frame_field_chirho(
            &mut hasher_chirho,
            ATTRIBUTION_BINDING_DOMAIN_CHIRHO.as_bytes(),
        );
        match self {
            Self::CauserChirho { principal_chirho } => {
                crate::framing_chirho::frame_field_chirho(&mut hasher_chirho, b"causer");
                crate::framing_chirho::frame_field_chirho(
                    &mut hasher_chirho,
                    principal_chirho.as_bytes(),
                );
            }
            Self::PlatformChirho => {
                crate::framing_chirho::frame_field_chirho(&mut hasher_chirho, b"platform");
            }
            Self::PolicyChirho { policy_ref_chirho } => {
                crate::framing_chirho::frame_field_chirho(&mut hasher_chirho, b"policy");
                crate::framing_chirho::frame_field_chirho(
                    &mut hasher_chirho,
                    policy_ref_chirho.0.as_bytes(),
                );
            }
        }
        hasher_chirho.finalize().to_hex().to_string()
    }
}

/// The cross-zone anchor (frozen §11.5, F4). Carried on the FIRST record of a new epoch; it binds the
/// handoff point into the chain (chain-CONTINUITY). Freshness of that point is A6 Raft election
/// safety, NOT this field.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrossZoneAnchorChirho {
    pub inherited_epoch_chirho: ShardEpochChirho,
    pub inherited_seq_chirho: u64,
    pub inherited_digest_chirho: DigestChirho,
}

/// The real signed record (frozen §11.1). `sig`/`key_id` are label-only (never trust-selection — the
/// SegmentContinuityPort idiom). The signed content is this record MINUS `sig`
/// ([`LedgerRecordChirho::signed_content_chirho`]); the record digest is BLAKE3 over the signed line
/// exactly as stored, so `prev` binds signatures into the chain. `schema` is the SCHEMA-FIRST wire
/// tag (A3): every stored line self-describes as `ledger-record-v1-chirho` before any field is
/// trusted — the canonical codec (`wire_chirho`) fail-closes emit AND parse on a wrong tag.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerRecordChirho {
    pub schema_chirho: String,
    pub format_version_chirho: u32,
    pub seq_chirho: u64,
    pub prev_chirho: DigestChirho,
    pub epoch_chirho: ShardEpochChirho,
    pub hlc_chirho: HlcChirho,
    pub legs_chirho: Vec<LedgerLegChirho>,
    pub op_chirho: LedgerOpChirho,
    pub idempotency_key_chirho: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance_chirho: Option<DigestChirho>,
    pub attribution_chirho: AttributionChirho,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor_chirho: Option<CrossZoneAnchorChirho>,
    pub sig_chirho: String,
    pub key_id_chirho: String,
}

impl LedgerRecordChirho {
    /// The sign-message view: this record MINUS `sig` (frozen §11.6 sign-then-attach). The
    /// EXHAUSTIVE destructure (no `..`) makes adding a record field without classifying it into the
    /// signed content a COMPILE error — a field can never silently ride outside the signature.
    pub fn signed_content_chirho(&self) -> LedgerRecordSignedContentViewChirho<'_> {
        let LedgerRecordChirho {
            schema_chirho,
            format_version_chirho,
            seq_chirho,
            prev_chirho,
            epoch_chirho,
            hlc_chirho,
            legs_chirho,
            op_chirho,
            idempotency_key_chirho,
            provenance_chirho,
            attribution_chirho,
            anchor_chirho,
            sig_chirho: _,
            key_id_chirho,
        } = self;
        LedgerRecordSignedContentViewChirho {
            schema_chirho,
            format_version_chirho: *format_version_chirho,
            seq_chirho: *seq_chirho,
            prev_chirho,
            epoch_chirho: *epoch_chirho,
            hlc_chirho,
            legs_chirho,
            op_chirho,
            idempotency_key_chirho,
            provenance_chirho: provenance_chirho.as_ref(),
            attribution_chirho,
            anchor_chirho: anchor_chirho.as_ref(),
            key_id_chirho,
        }
    }
}

/// Serialize-only borrow of a record's SIGNED CONTENT (record minus `sig`, §11.6). Field order and
/// serde attrs mirror [`LedgerRecordChirho`] exactly, so the sign-message bytes are the stored-line
/// bytes with only the `sig` key absent. Never deserialized — verification reconstructs this view
/// from a parsed record; the wire carries only full records.
#[derive(Serialize)]
pub struct LedgerRecordSignedContentViewChirho<'record_chirho> {
    pub schema_chirho: &'record_chirho str,
    pub format_version_chirho: u32,
    pub seq_chirho: u64,
    pub prev_chirho: &'record_chirho DigestChirho,
    pub epoch_chirho: ShardEpochChirho,
    pub hlc_chirho: &'record_chirho HlcChirho,
    pub legs_chirho: &'record_chirho [LedgerLegChirho],
    pub op_chirho: &'record_chirho LedgerOpChirho,
    pub idempotency_key_chirho: &'record_chirho str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provenance_chirho: Option<&'record_chirho DigestChirho>,
    pub attribution_chirho: &'record_chirho AttributionChirho,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anchor_chirho: Option<&'record_chirho CrossZoneAnchorChirho>,
    pub key_id_chirho: &'record_chirho str,
}

/// The journal GENESIS record (frozen §11.6 genesis biconditional): `gen-0 ⟺ no prev ⟺ no
/// post-state legs` — a DISTINCT schema-first type, so a genesis line structurally CANNOT carry a
/// `prev` or legs (illegal states unrepresentable, stronger than an empty vec). Its stored-line
/// digest NAMES the journal instance; record seq=1's `prev` is exactly that digest. Accounts open
/// lazily (first leg = zero-baseline); membership is the static cluster declaration (§11.0).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerGenesisRecordChirho {
    pub schema_chirho: String,
    pub format_version_chirho: u32,
    pub cluster_id_chirho: crate::ids_chirho::ClusterIdChirho,
    pub epoch_chirho: ShardEpochChirho,
    pub hlc_chirho: HlcChirho,
    pub sig_chirho: String,
    pub key_id_chirho: String,
}

impl LedgerGenesisRecordChirho {
    /// The genesis sign-message view (genesis minus `sig`) — same exhaustive-destructure law as
    /// [`LedgerRecordChirho::signed_content_chirho`].
    pub fn signed_content_chirho(&self) -> LedgerGenesisSignedContentViewChirho<'_> {
        let LedgerGenesisRecordChirho {
            schema_chirho,
            format_version_chirho,
            cluster_id_chirho,
            epoch_chirho,
            hlc_chirho,
            sig_chirho: _,
            key_id_chirho,
        } = self;
        LedgerGenesisSignedContentViewChirho {
            schema_chirho,
            format_version_chirho: *format_version_chirho,
            cluster_id_chirho,
            epoch_chirho: *epoch_chirho,
            hlc_chirho,
            key_id_chirho,
        }
    }
}

/// Serialize-only borrow of a genesis record's signed content (genesis minus `sig`, §11.6).
#[derive(Serialize)]
pub struct LedgerGenesisSignedContentViewChirho<'record_chirho> {
    pub schema_chirho: &'record_chirho str,
    pub format_version_chirho: u32,
    pub cluster_id_chirho: &'record_chirho crate::ids_chirho::ClusterIdChirho,
    pub epoch_chirho: ShardEpochChirho,
    pub hlc_chirho: &'record_chirho HlcChirho,
    pub key_id_chirho: &'record_chirho str,
}
