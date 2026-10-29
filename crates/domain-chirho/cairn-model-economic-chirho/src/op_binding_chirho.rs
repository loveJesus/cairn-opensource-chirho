// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

//! The frozen ledger schema-v2 operation binding: the signed-row semantics of a W3 money
//! operation (op identity, generation, kind, writer-authority context, allowance refs, provider
//! call id, witness refs). J0a freezes the SHAPE and its complete per-kind field-presence matrix;
//! all production authority stays INACTIVE until J0b activates it. Because J0a is the one and only
//! schema freeze ("no later J adds a field or retargets v2"), this matrix is exhaustive.

use cairn_core_chirho::model_chirho::HashChirho;
use serde::{Deserialize, Serialize};

/// The signed wire label for a schema-v2 ledger entry. Byte-stable; never inferred from a Rust
/// identifier spelling.
pub const LEDGER_ENTRY_SCHEMA_V2_CHIRHO: &str = "ledger-entry-v2-chirho";

/// The typed money-operation kind. Wire discriminants are pinned with explicit `serde(rename)` so a
/// Rust identifier rename can never silently change a signed byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OpKindChirho {
    #[serde(rename = "charge")]
    ChargeChirho,
    #[serde(rename = "reserve-hold")]
    ReserveHoldChirho,
    #[serde(rename = "settle-hold")]
    SettleHoldChirho,
    #[serde(rename = "release-hold")]
    ReleaseHoldChirho,
    #[serde(rename = "suspense")]
    SuspenseChirho,
    #[serde(rename = "refund")]
    RefundChirho,
    #[serde(rename = "grant-credit")]
    GrantCreditChirho,
    #[serde(rename = "top-up")]
    TopUpChirho,
    #[serde(rename = "payout-reserve")]
    PayoutReserveChirho,
    #[serde(rename = "payout-call-authorized")]
    PayoutCallAuthorizedChirho,
    #[serde(rename = "payout-settle")]
    PayoutSettleChirho,
    /// Pre-call terminal cancellation of a reserved-but-never-called payout (releases from
    /// `reserved-escrow`). Carries NO resolution witness — nothing reached the provider.
    #[serde(rename = "payout-pre-call-release")]
    PayoutPreCallReleaseChirho,
    /// Post-call manual release of a payout whose provider call is definitively no-transfer
    /// (releases from `call-authorized-escrow`). REQUIRES the bound `ConfirmedNoTransferManual`
    /// resolution witness.
    #[serde(rename = "payout-post-call-release")]
    PayoutPostCallReleaseChirho,
    #[serde(rename = "install-allowance")]
    InstallAllowanceChirho,
    #[serde(rename = "realtime-reserve")]
    RealtimeReserveChirho,
    #[serde(rename = "realtime-settle")]
    RealtimeSettleChirho,
    #[serde(rename = "realtime-release")]
    RealtimeReleaseChirho,
    #[serde(rename = "operator-transfer")]
    OperatorTransferChirho,
    #[serde(rename = "operator-grant")]
    OperatorGrantChirho,
    #[serde(rename = "identity-grant")]
    IdentityGrantChirho,
    #[serde(rename = "conversion")]
    ConversionChirho,
}

/// The complete signed-field requirement classification of one `OpKindChirho`: which optional v2
/// binding fields the kind MUST carry. This is the frozen per-kind matrix in ONE place.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpKindFieldRequirementsChirho {
    /// The OUTBOUND payout family binds a `provider_call_id`; no other kind does (top-up is inbound).
    pub provider_call_id_chirho: bool,
    /// Credit/settle/transition-from-origin kinds bind an `origin_op_ref`.
    pub origin_op_ref_chirho: bool,
    /// Witness-bearing kinds (top-up event; payout settle / post-call release) require ≥1 witness.
    pub witness_chirho: bool,
    /// Spend kinds MAY carry allowance refs; every other kind MUST carry none.
    pub allowance_spend_chirho: bool,
}

impl OpKindChirho {
    /// The single, COMPILE-EXHAUSTIVE per-kind field classification (no wildcard arm): adding a new
    /// `OpKindChirho` variant is a compile error here until its complete signed-field requirements
    /// are reviewed, so a later variant can never silently default onto the frozen v2 schema. The
    /// four predicates below delegate here.
    pub fn field_requirements_chirho(&self) -> OpKindFieldRequirementsChirho {
        use OpKindChirho::*;
        // (provider_call_id, origin_op_ref, witness, allowance_spend)
        let (provider_chirho, origin_chirho, witness_chirho, spend_chirho) = match self {
            ChargeChirho => (false, false, false, true),
            ReserveHoldChirho => (false, false, false, true),
            SettleHoldChirho => (false, true, false, false),
            ReleaseHoldChirho => (false, true, false, false),
            SuspenseChirho => (false, false, false, false),
            RefundChirho => (false, true, false, false),
            GrantCreditChirho => (false, false, false, false),
            TopUpChirho => (false, false, true, false),
            PayoutReserveChirho => (true, false, false, true),
            PayoutCallAuthorizedChirho => (true, true, false, false),
            PayoutSettleChirho => (true, true, true, false),
            PayoutPreCallReleaseChirho => (true, true, false, false),
            PayoutPostCallReleaseChirho => (true, true, true, false),
            InstallAllowanceChirho => (false, false, false, false),
            RealtimeReserveChirho => (false, false, false, true),
            RealtimeSettleChirho => (false, true, false, false),
            RealtimeReleaseChirho => (false, true, false, false),
            OperatorTransferChirho => (false, false, false, false),
            OperatorGrantChirho => (false, false, false, false),
            IdentityGrantChirho => (false, false, false, false),
            ConversionChirho => (false, false, false, false),
        };
        OpKindFieldRequirementsChirho {
            provider_call_id_chirho: provider_chirho,
            origin_op_ref_chirho: origin_chirho,
            witness_chirho,
            allowance_spend_chirho: spend_chirho,
        }
    }

    /// The OUTBOUND payout family binds a `provider_call_id`; top-up is INBOUND (event witness).
    pub fn requires_provider_call_id_chirho(&self) -> bool {
        self.field_requirements_chirho().provider_call_id_chirho
    }

    /// Kinds that credit, settle, or transition FROM an origin operation bind an `origin_op_ref`.
    pub fn requires_origin_op_ref_chirho(&self) -> bool {
        self.field_requirements_chirho().origin_op_ref_chirho
    }

    /// Witness-bearing kinds: the top-up event witness and the two post-provider payout outcomes.
    pub fn requires_witness_chirho(&self) -> bool {
        self.field_requirements_chirho().witness_chirho
    }

    /// Spend kinds MAY carry the ordered allowance-ref set; every other kind MUST carry none.
    pub fn is_spend_kind_chirho(&self) -> bool {
        self.field_requirements_chirho().allowance_spend_chirho
    }
}

/// The money-writer authority context: which authority mode signed this v2 row. `LocalFenceV1Chirho`
/// is the ONLY mode W3 accepts. `ElectedTermV1Chirho` is defined so the schema is a drop-in for the
/// gated A6 election, but it has ZERO production constructors and W3 fails closed on it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode_chirho", deny_unknown_fields)]
pub enum MoneyWriterAuthorityContextChirho {
    /// The local single-writer fence authority. Binds a stable, path-free, deployment-injective
    /// money-group identity + the local fence group digest + the local fence epoch. Carries no
    /// quorum proof.
    #[serde(rename = "local-fence-v1")]
    LocalFenceV1Chirho {
        stable_group_id_chirho: HashChirho,
        local_group_digest_chirho: HashChirho,
        local_epoch_chirho: u64,
    },
    /// The future elected-term authority (gated A6). Present for schema drop-in ONLY — never
    /// constructed in production, never accepted by W3.
    #[serde(rename = "elected-term-v1")]
    ElectedTermV1Chirho {
        stable_group_id_chirho: HashChirho,
        election_config_digest_chirho: HashChirho,
        term_chirho: u64,
        leader_chirho: String,
        quorum_commit_certificate_ref_chirho: HashChirho,
    },
}

impl MoneyWriterAuthorityContextChirho {
    /// W3 accepts only `LocalFenceV1Chirho`; `ElectedTermV1Chirho` is inert (gated A6).
    pub fn is_local_fence_chirho(&self) -> bool {
        matches!(
            self,
            MoneyWriterAuthorityContextChirho::LocalFenceV1Chirho { .. }
        )
    }
}

/// One consumed allowance reference in the ordered spend set: which cap scope, which generation of
/// that cap, and which window (the lifetime sentinel is a first-class window id).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowanceRefChirho {
    pub scope_chirho: String,
    pub generation_chirho: u64,
    pub window_id_chirho: String,
}

/// The lifetime (no-window) sentinel window id. Backfill maps every existing cap to this.
pub const ALLOWANCE_WINDOW_LIFETIME_CHIRHO: &str = "lifetime-chirho";

/// The frozen schema-v2 operation binding carried on a v2 ledger entry. A v2 row is classifiable
/// authoritative money on its own AND attributable to exactly one intent generation's plan.
///
/// `deny_unknown_fields` freezes the exact v2 sub-object keyset: a v2 binding with any unknown
/// (top-level or nested) field FAILS to deserialize rather than silently parse-and-dropping it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpBindingChirho {
    /// The domain-hashed operation identity (op key).
    pub op_id_chirho: HashChirho,
    /// The canonical operation digest binding every field that changes the legal transition.
    pub op_digest_chirho: HashChirho,
    /// The intent generation this row belongs to (LOCAL recovery identity).
    pub intent_generation_chirho: u64,
    /// The planned-body digest this row must byte/digest-match.
    pub planned_body_digest_chirho: HashChirho,
    /// The typed money-operation kind.
    pub op_kind_chirho: OpKindChirho,
    /// The money-writer authority context (W3: `LocalFenceV1Chirho` only).
    pub money_writer_authority_context_chirho: MoneyWriterAuthorityContextChirho,
    /// The ordered allowance-ref set consumed (spend kinds only); empty otherwise.
    #[serde(default)]
    pub allowance_refs_chirho: Vec<AllowanceRefChirho>,
    /// The origin op ref (settle/release/refund/marker kinds); absent otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_op_ref_chirho: Option<HashChirho>,
    /// The stable outbound-payout external-effect id (payout family ONLY); absent otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_call_id_chirho: Option<HashChirho>,
    /// Provider witness refs: the top-up event witness, or the payout settle/post-call-release
    /// resolution witness. Present only on witness-bearing kinds; empty otherwise.
    #[serde(default)]
    pub witness_refs_chirho: Vec<HashChirho>,
}

/// The J0a shape-validation error kinds for the per-kind field-presence matrix. These are SHAPE
/// errors; production authority rejection of v2 is a separate, additional gate (J0a is
/// authority-inert).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OpBindingShapeErrorChirho {
    /// A v2 row must carry a `LocalFenceV1Chirho` authority context (W3 never accepts elected-term).
    NonLocalFenceAuthorityChirho,
    /// The `provider_call_id` presence does not match the kind (payout family requires it; every
    /// other kind, including top-up, forbids it).
    ProviderCallIdKindMismatchChirho,
    /// The `origin_op_ref` presence does not match the kind.
    OriginOpRefKindMismatchChirho,
    /// The `witness_refs` presence does not match the kind (witness-bearing kinds require ≥1; every
    /// other kind forbids any).
    WitnessRefsKindMismatchChirho,
    /// A non-spend kind carries allowance refs (allowance consumption smuggled onto a
    /// credit/grant/settle/release row).
    AllowanceRefsOnNonSpendKindChirho,
}

impl OpBindingChirho {
    /// Validate the complete per-kind field-presence matrix of a v2 binding (does NOT accept
    /// authority — J0a is inert). Returns the first shape violation, if any.
    pub fn validate_shape_chirho(&self) -> Result<(), OpBindingShapeErrorChirho> {
        if !self
            .money_writer_authority_context_chirho
            .is_local_fence_chirho()
        {
            return Err(OpBindingShapeErrorChirho::NonLocalFenceAuthorityChirho);
        }
        if self.op_kind_chirho.requires_provider_call_id_chirho()
            != self.provider_call_id_chirho.is_some()
        {
            return Err(OpBindingShapeErrorChirho::ProviderCallIdKindMismatchChirho);
        }
        if self.op_kind_chirho.requires_origin_op_ref_chirho()
            != self.origin_op_ref_chirho.is_some()
        {
            return Err(OpBindingShapeErrorChirho::OriginOpRefKindMismatchChirho);
        }
        // Witness-bearing kinds require ≥1 witness; every other kind requires none. Equivalent to
        // `requires_witness() != witness_present`, simplified (`a != !b` ⟺ `a == b`).
        if self.op_kind_chirho.requires_witness_chirho() == self.witness_refs_chirho.is_empty() {
            return Err(OpBindingShapeErrorChirho::WitnessRefsKindMismatchChirho);
        }
        if !self.op_kind_chirho.is_spend_kind_chirho() && !self.allowance_refs_chirho.is_empty() {
            return Err(OpBindingShapeErrorChirho::AllowanceRefsOnNonSpendKindChirho);
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "op_binding_tests_chirho.rs"]
mod tests_chirho;
