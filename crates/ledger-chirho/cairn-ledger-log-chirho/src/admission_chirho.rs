// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! B-1: the money-fence ADMISSION core — the one gate a candidate record passes before it may touch
//! the journal. Pure decision logic over (candidate, true-current-state views); zero I/O. Admission
//! alone issues the log-owned [`AdmittedRecordChirho`] token (B1 ruling: private construction — a
//! raw `(legs, op)` can never masquerade as admitted), after: wire canonicality, seq/prev/epoch
//! fencing, HLC monotonicity, idempotency, the INDEPENDENT §11.10 grammar (coded from the table,
//! NEVER shared with the reference oracle — the independence law), membership (R1), kind-identity
//! binding (R-KIND), per-stable-kind Σ=0 (R5a), mint/burn authority + supply (R2), and the F1/F4
//! append-time fence (recompute EVERY leg's post from the true head — precomputed posts are never
//! trusted). Unavailable verifier ⇒ REJECT (fail-closed; finality/settlement are CF2, so every
//! counterpart-bearing or escrow record refuses in CF1).

use cairn_ledger_model_chirho::asset_op_chirho::{
    AssetOpChirho, AssetOpRoundingErrorChirho, RoundingChirho,
};
use cairn_ledger_model_chirho::counterpart_chirho::CounterpartNullifierChirho;
use cairn_ledger_model_chirho::ids_chirho::{
    AccountIdChirho, AssetKindIdChirho, AssetKindRefChirho, ClusterIdChirho, DigestChirho,
    MoneyGroupIdChirho, SettlementChannelIdChirho, TransferIdChirho,
};
use cairn_ledger_model_chirho::record_chirho::{
    CrossZoneAnchorChirho, HlcChirho, LedgerLegChirho, LedgerOpChirho, LedgerRecordChirho,
    LegDeltaChirho, LegPostStateChirho,
};
use cairn_ledger_model_chirho::wire_chirho::{
    canonical_ledger_record_line_chirho, WireErrorChirho,
};
use cairn_ledger_model_chirho::ShardEpochChirho;
use std::collections::{BTreeMap, BTreeSet};

/// An account's membership standing at a given epoch (§11.0 static cluster declaration; R1.4 makes
/// it epoch-aware so a revoked member cannot transact under the epoch of its revocation).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MembershipStatusChirho {
    MemberChirho,
    RevokedChirho,
    NonMemberChirho,
}

/// The epoch-aware cluster roster view (B-2 supplies the declared-membership implementation; REDs
/// stub it — admission attacks the WIRING, the roster's own integrity is B-2's).
pub trait MembershipViewChirho {
    fn status_chirho(
        &self,
        account_chirho: &AccountIdChirho,
        epoch_chirho: ShardEpochChirho,
    ) -> MembershipStatusChirho;
}

/// A resolved asset-kind policy REVISION view (§11.7): the stable identity this revision belongs
/// to, its mint-authority mode, and the immutable rounding rule checked by typed money doors. The
/// full policy record (precision, expiry, residency...) grows here without changing the binding
/// law.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IdempotencyWindowPolicyViewChirho {
    pub idempotency_horizon_ms_chirho: u64,
    pub retry_finality_horizon_ms_chirho: u64,
}

/// The retention-only answer for a policy ref already carried by a VERIFIED journal record.
/// Unlike [`KindResolutionChirho`], this type can never return an admission policy: its only
/// authority is how long rebuildable dedup evidence remains retained.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordedRetentionWindowChirho {
    BoundedChirho(IdempotencyWindowPolicyViewChirho),
    /// Unknown refs and legacy policies retain indefinitely. Failure may over-retain evidence;
    /// it can never shorten the window and re-admit an old request.
    RetainIndefinitelyChirho,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KindPolicyViewChirho {
    pub kind_id_chirho: AssetKindIdChirho,
    pub mint_authority_chirho: MintAuthorityPolicyChirho,
    pub rounding_chirho: RoundingChirho,
    /// The OWNER principal of this kind's designated settlement account (CF2 sub-ruling a):
    /// EscrowFinalize's paired Credit must target LogId(this owner, this kind). None = no
    /// settlement configured = Finalize refuses fail-closed for this kind.
    pub settlement_owner_chirho: Option<String>,
    /// CF3 W-law policy projected from the signed kind registry. `None` means legacy-unpruned;
    /// callers may never invent a finite default for an absent policy.
    pub idempotency_window_chirho: Option<IdempotencyWindowPolicyViewChirho>,
}

/// The CURRENT policy coordinate for continuing an already-admitted stable-kind obligation.
/// This is deliberately a third, non-substitutable registry question: ordinary admission still
/// resolves the caller-carried ref strictly, while the CF3 terminal door derives the stable kind
/// from a verified intent and asks the registry which CURRENT ref must finish that live Hold.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CurrentContinuationPolicyChirho {
    pub kind_policy_ref_chirho: AssetKindRefChirho,
    pub policy_chirho: KindPolicyViewChirho,
}

/// Who may mint a kind (§11.7): provider-receipt-backed money, bounded platform policy, or nobody.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MintAuthorityPolicyChirho {
    ProviderReceiptChirho,
    PlatformPolicyChirho { max_supply_chirho: Option<u64> },
    ClosedChirho,
}

/// How a kind-policy ref resolves against the registry's CURRENT state. Three states because
/// "was valid, isn't current" ≠ "never existed": admitting under a SUPERSEDED ref is the
/// policy-downgrade attack (e.g. minting under the old uncapped revision after a cap landed), and
/// its refusal must be distinctly typed so callers can never confuse it with a typo'd ref.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KindResolutionChirho {
    CurrentChirho(KindPolicyViewChirho),
    SupersededChirho,
    UnknownChirho,
}

impl KindResolutionChirho {
    /// Admission's uniform mapping: only the CURRENT policy admits; superseded and unknown refuse
    /// with their DISTINCT typed rejects (fail-closed both ways).
    pub fn into_current_chirho(self) -> Result<KindPolicyViewChirho, AdmissionRejectChirho> {
        match self {
            KindResolutionChirho::CurrentChirho(policy_chirho) => Ok(policy_chirho),
            KindResolutionChirho::SupersededChirho => {
                Err(AdmissionRejectChirho::SupersededKindPolicyChirho)
            }
            KindResolutionChirho::UnknownChirho => {
                Err(AdmissionRejectChirho::UnknownKindPolicyChirho)
            }
        }
    }
}

/// The registry that resolves a leg's `kind_policy_ref` to its policy view — the R-KIND binding act
/// (`resolve(kind_policy_ref).kind_id == account.kind_id`) is a REGISTRY act the arithmetic oracle
/// structurally cannot perform. Unknown/Superseded ⇒ fail-closed (distinctly typed).
pub trait KindRegistryViewChirho {
    fn resolve_chirho(&self, policy_ref_chirho: &AssetKindRefChirho) -> KindResolutionChirho;

    /// Resolve ONLY the current retention window for a ref carried by verified history. The
    /// default handles current refs and fails safe for superseded/unknown refs; the production
    /// signed registry overrides this so a superseded ref maps to its stable kind's CURRENT
    /// monotone-nondecreasing window. Admission must continue to use [`Self::resolve_chirho`].
    /// Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/cf3-effect-commit-second-seat-chirho.md`.
    fn resolve_recorded_ref_retention_window_chirho(
        &self,
        policy_ref_chirho: &AssetKindRefChirho,
    ) -> RecordedRetentionWindowChirho {
        match self.resolve_chirho(policy_ref_chirho) {
            KindResolutionChirho::CurrentChirho(policy_chirho) => policy_chirho
                .idempotency_window_chirho
                .map(RecordedRetentionWindowChirho::BoundedChirho)
                .unwrap_or(RecordedRetentionWindowChirho::RetainIndefinitelyChirho),
            KindResolutionChirho::SupersededChirho | KindResolutionChirho::UnknownChirho => {
                RecordedRetentionWindowChirho::RetainIndefinitelyChirho
            }
        }
    }

    /// Resolve the CURRENT continuation coordinate for a stable kind already bound by verified
    /// history. No caller-carried ref enters this method, and its return type cannot substitute
    /// for [`Self::resolve_chirho`]. The CF3 terminal door is the sole production consumer.
    /// Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/cf3-effect-commit-second-seat-chirho.md`.
    fn resolve_current_continuation_by_kind_chirho(
        &self,
        _kind_id_chirho: &AssetKindIdChirho,
    ) -> Option<CurrentContinuationPolicyChirho> {
        None
    }
}

/// A mint/burn authority-evidence verdict. The verifier RESOLVES the evidence digest and checks the
/// grant covers this kind (R2.1/R2.2 — presence of a digest is NEVER sufficient).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorityVerdictChirho {
    VerifiedChirho,
    UnverifiedChirho,
    WrongKindChirho,
}

/// The mint/burn authority verifier view (B-2 supplies the signed-grant implementation).
pub trait AuthorityVerifierViewChirho {
    fn verify_mint_chirho(
        &self,
        evidence_chirho: &DigestChirho,
        kind_id_chirho: &AssetKindIdChirho,
    ) -> AuthorityVerdictChirho;
    fn verify_burn_chirho(
        &self,
        evidence_chirho: &DigestChirho,
        kind_id_chirho: &AssetKindIdChirho,
    ) -> AuthorityVerdictChirho;
}

/// The TRUE current state under the append lock — everything admission needs, as borrowed views.
/// The caller (B-2's journal engine) is responsible for these being CURRENT (the F1 suffix-replay
/// law); admission is then a pure function of candidate × context.
/// The unconsumed-holds index key: the EXACT (account, saga, step) triple (CF2 P3 — same-saga-
/// F3a (§11.8a): resolve finality-proof BYTES by content address. DUMB view — admission re-hashes,
/// parses, and equality-checks every bound field itself (claude2 port ruling #5040).
pub trait FinalityProofBytesViewChirho {
    fn resolve_chirho(&self, proof_ref_chirho: &DigestChirho) -> Option<Vec<u8>>;
}

/// F3a: the per-money-group SOURCE trust-root verify predicate (canonical content + sig -> bool).
/// No parsing, no key material crosses into admission.
pub trait SourceRootVerifyViewChirho {
    fn verify_chirho(
        &self,
        money_group_chirho: &MoneyGroupIdChirho,
        signed_content_chirho: &str,
        sig_chirho: &str,
    ) -> bool;
}

/// F3a (gpt C2, the R3 role gate): settlement-authorization EVIDENCE for this transfer/channel —
/// signed saga/provenance evidence resolved by the composition root, never caller self-declaration.
pub trait SettlementAuthorizationViewChirho {
    fn verify_chirho(
        &self,
        transfer_id_chirho: &TransferIdChirho,
        channel_chirho: &SettlementChannelIdChirho,
        settlement_account_chirho: &AccountIdChirho,
    ) -> bool;
}

/// The x-cluster admission composition (law v — COMPOSITIONAL ABSENCE): a journal composed
/// WITHOUT this bundle keeps the counterpart Transfer row ExplicitlyUnsupported; absence of
/// infrastructure never default-opens a money door.
#[derive(Clone, Copy)]
pub struct FinalityAdmissionViewsChirho<'views_chirho> {
    pub proofs_chirho: &'views_chirho dyn FinalityProofBytesViewChirho,
    pub source_roots_chirho: &'views_chirho dyn SourceRootVerifyViewChirho,
    pub settlement_authorizations_chirho: &'views_chirho dyn SettlementAuthorizationViewChirho,
}

/// DIFFERENT-step is a distinct, legal hold; only the exact triple is unique).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EscrowHoldKeyChirho {
    pub account_chirho: AccountIdChirho,
    pub saga_id_chirho: DigestChirho,
    pub step_chirho: u32,
}

pub struct AdmissionContextChirho<'context_chirho> {
    pub expected_seq_chirho: u64,
    pub expected_prev_chirho: &'context_chirho DigestChirho,
    pub current_epoch_chirho: ShardEpochChirho,
    pub tail_hlc_chirho: &'context_chirho HlcChirho,
    pub membership_chirho: &'context_chirho dyn MembershipViewChirho,
    pub kind_registry_chirho: &'context_chirho dyn KindRegistryViewChirho,
    pub authority_chirho: &'context_chirho dyn AuthorityVerifierViewChirho,
    /// Per-account TRUE head post-states; an ABSENT account is a lazily-opened zero baseline
    /// (§11.6 — its first leg establishes it).
    pub head_states_chirho: &'context_chirho BTreeMap<AccountIdChirho, LegPostStateChirho>,
    /// Cumulative NET supply per stable kind (minted − burned), for the R2.3 cap check.
    pub supply_by_kind_chirho: &'context_chirho BTreeMap<AssetKindIdChirho, u64>,
    /// Idempotency keys inside the live W-law window (duplicate ⇒ refuse; replay semantics are the
    /// caller's — admission never appends twice).
    pub recent_idempotency_keys_chirho: &'context_chirho BTreeSet<String>,
    /// The UNCONSUMED escrow holds (CF2): key = the exact (account, saga, step) triple; value =
    /// the held amount (the kind rides the account id). Hold refuses a duplicate key;
    /// Release/Finalize require the EXACT five-way match and consume it. The journal maintains
    /// this post-append and rebuilds it on replay (P2's load-side twin); O(active-holds).
    pub active_holds_chirho: &'context_chirho BTreeMap<EscrowHoldKeyChirho, u64>,
    /// THIS journal's cluster — the x-cluster claim's dst_cluster must equal it (law i).
    pub cluster_chirho: &'context_chirho ClusterIdChirho,
    /// The CONSUMED counterpart nullifiers (F3a law ii): first claim authoritative; the journal
    /// maintains this post-append and rebuilds it on replay. Prune horizon is a CF3 W-law
    /// coordinate (#5040 c2) — conservative default UNPRUNED.
    pub consumed_nullifiers_chirho: &'context_chirho BTreeSet<CounterpartNullifierChirho>,
    /// The x-cluster composition (law v): None keeps the counterpart row ExplicitlyUnsupported.
    pub finality_chirho: Option<FinalityAdmissionViewsChirho<'context_chirho>>,
    /// The §11.5 anchor law at ADMISSION: `Some(anchor)` exactly when this append is the FIRST
    /// record of a freshly-advanced epoch (the candidate must carry EXACTLY that anchor, binding
    /// the pre-advance tail); `None` in steady state (a candidate carrying any anchor is refused).
    pub expected_anchor_chirho: Option<&'context_chirho CrossZoneAnchorChirho>,
}

/// Why admission REFUSED — typed, dimension-precise (the RED catalog asserts the reason lands on
/// the intended dimension, so a missing authority check can never hide behind an incidental
/// arithmetic reject). These names are MINE; the reference oracle's reject enum is independently
/// coded (the independence law) and the differential maps categories.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdmissionRejectChirho {
    WireChirho {
        error_chirho: WireErrorChirho,
    },
    SeqMismatchChirho {
        expected_chirho: u64,
        found_chirho: u64,
    },
    PrevMismatchChirho,
    EpochMismatchChirho {
        expected_chirho: ShardEpochChirho,
        found_chirho: ShardEpochChirho,
    },
    HlcNotMonotoneChirho,
    IdempotencyDuplicateChirho,
    /// §11.5: the candidate's anchor is not exactly what this append position requires (a missing
    /// anchor on an epoch's first record, a stray anchor in steady state, or a non-binding one).
    AnchorMismatchChirho,
    /// CF1 ExplicitlyUnsupported: bare Credit/Debit, Compensation, the escrow family (R4), and the
    /// x-cluster settlement Transfer form (any counterpart-bearing Transfer — the §11.10
    /// discriminator: never BadShape, never silently internal).
    UnsupportedOperationChirho,
    BadShapeChirho {
        detail_chirho: String,
    },
    NonMemberChirho {
        owner_chirho: String,
    },
    RevokedMemberChirho {
        owner_chirho: String,
    },
    UnknownKindPolicyChirho,
    /// The ref WAS a valid policy revision but has been superseded — new admissions must use the
    /// kind's CURRENT ref (the policy-downgrade-attack refusal; distinct from Unknown).
    SupersededKindPolicyChirho,
    /// An EscrowHold names an (account, saga, step) triple that already has an UNCONSUMED hold
    /// (CF2 P3 — the exact-triple uniqueness law).
    DuplicateEscrowHoldChirho,
    /// A Release/Finalize names no UNCONSUMED hold matching the exact five-way
    /// (account, kind, amount, saga, step) coordinate.
    UnknownEscrowHoldChirho,
    /// EscrowFinalize's Credit leg does not target the kind's designated settlement account
    /// from the CURRENT policy (or no settlement is configured — fail-closed either way).
    SettlementTargetMismatchChirho,
    /// F3a: the claim's finality_proof_ref resolves to nothing in the composed proof view.
    CounterpartProofMissingChirho,
    /// F3a: resolved proof bytes fail content-address/canonical-parse/source-root-signature.
    CounterpartProofInvalidChirho {
        detail_chirho: String,
    },
    /// F3a law i: a bound field diverges (locator, burn summary, leg binding, kind revision,
    /// kind stability, or destination cluster) — each detail names its dimension.
    CounterpartBindingMismatchChirho {
        detail_chirho: String,
    },
    /// F3a law ii: the carried nullifier does not equal its derivation (a chosen nullifier).
    CounterpartNullifierMismatchChirho,
    /// F3a law ii: the derived nullifier was already consumed in this journal (replay).
    CounterpartNullifierConsumedChirho,
    /// F3a law iv (R3): no verified settlement authorization for (transfer, channel, account).
    SettlementAuthorizationRefusedChirho,
    KindIdentityMismatchChirho,
    KindConservationChirho {
        kind_id_chirho: AssetKindIdChirho,
    },
    MintClosedKindChirho,
    MintAuthorityUnverifiedChirho,
    MintAuthorityWrongKindChirho,
    ZeroAmountMintChirho,
    SupplyCapExceededChirho,
    BurnAuthorityUnverifiedChirho,
    BurnAuthorityWrongKindChirho,
    ZeroAmountBurnChirho,
    AssetOpRoundingChirho {
        error_chirho: AssetOpRoundingErrorChirho,
    },
    AssetOpRecordMismatchChirho {
        detail_chirho: String,
    },
    /// F1: a leg's carried post-state ≠ the fold recomputed from the TRUE current head.
    PostStateMismatchChirho {
        leg_index_chirho: usize,
    },
    /// F4: spendable (credits − debits − held) would fall below zero.
    SpendableFloorChirho {
        leg_index_chirho: usize,
    },
    /// Checked counter math refused (overflow/underflow) — money never wraps.
    ArithmeticChirho,
}

/// Rebuildable retention law derived from the SAME immutable policy resolutions admission used
/// for the record's legs. Construction is private to admission's token: callers cannot invent a
/// shorter horizon or omit one touched policy ref.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IdempotencyRetentionChirho {
    /// No legs, or at least one touched policy has no CF3 window. These records stay in the legacy
    /// unpruned set through CF6 regenesis; no finite age is invented for them.
    LegacyUnprunedChirho {
        policy_refs_chirho: Vec<AssetKindRefChirho>,
    },
    /// Every touched policy has a window. Both horizons are the MAX across deduplicated refs:
    /// retain longer, never shorter.
    BoundedChirho {
        policy_refs_chirho: Vec<AssetKindRefChirho>,
        idempotency_horizon_ms_chirho: u64,
        retry_finality_horizon_ms_chirho: u64,
    },
}

/// The log-owned admitted-record token (B1): its EXISTENCE is the proof that full admission passed.
/// Construction is private to this module — no other code (in this crate or any other) can mint
/// one. The differential harness and the append path consume it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmittedRecordChirho {
    record_chirho: LedgerRecordChirho,
    retention_chirho: IdempotencyRetentionChirho,
}

impl AdmittedRecordChirho {
    pub fn record_chirho(&self) -> &LedgerRecordChirho {
        &self.record_chirho
    }

    pub fn into_record_chirho(self) -> LedgerRecordChirho {
        self.record_chirho
    }

    pub fn retention_chirho(&self) -> &IdempotencyRetentionChirho {
        &self.retention_chirho
    }

    pub fn into_parts_chirho(self) -> (LedgerRecordChirho, IdempotencyRetentionChirho) {
        (self.record_chirho, self.retention_chirho)
    }
}

/// Admits a plain checked money request. The immutable registry supplies the kind identity and
/// policy; callers cannot supply a rounding rule. Every record leg must carry the AssetOp's exact
/// kind, policy revision, and amount before the ordinary ledger laws run.
/// Workflow: `spec-chirho/workflows-chirho/undo-chirho/static-undo-plan-design-chirho.md` section 11.
pub fn admit_plain_asset_op_chirho(
    context_chirho: &AdmissionContextChirho<'_>,
    asset_op_chirho: &AssetOpChirho,
    candidate_chirho: LedgerRecordChirho,
) -> Result<AdmittedRecordChirho, AdmissionRejectChirho> {
    resolve_asset_op_policy_chirho(context_chirho, asset_op_chirho)?;
    asset_op_chirho
        .validate_plain_move_rounding_chirho()
        .map_err(|error_chirho| AdmissionRejectChirho::AssetOpRoundingChirho { error_chirho })?;
    validate_asset_op_record_coordinate_chirho(asset_op_chirho, &candidate_chirho)?;
    if candidate_chirho
        .legs_chirho
        .iter()
        .any(|leg_chirho| leg_chirho.amount_chirho != asset_op_chirho.amount_chirho)
    {
        return Err(AdmissionRejectChirho::AssetOpRecordMismatchChirho {
            detail_chirho: "plain AssetOp amount does not match every ledger leg".to_owned(),
        });
    }
    admit_chirho(context_chirho, candidate_chirho)
}

/// Admits one rounded split. The AssetOp names one derived part; the same transfer record must carry
/// at least one counterpart part, and ordinary per-kind conservation decides whether they exactly
/// absorb the whole. Rounding therefore decides remainder placement, never value creation.
/// Workflow: `spec-chirho/workflows-chirho/undo-chirho/static-undo-plan-design-chirho.md` section 11.
pub fn admit_derived_asset_op_chirho(
    context_chirho: &AdmissionContextChirho<'_>,
    asset_op_chirho: &AssetOpChirho,
    candidate_chirho: LedgerRecordChirho,
) -> Result<AdmittedRecordChirho, AdmissionRejectChirho> {
    let policy_chirho = resolve_asset_op_policy_chirho(context_chirho, asset_op_chirho)?;
    asset_op_chirho
        .validate_derived_rounding_chirho(policy_chirho.rounding_chirho)
        .map_err(|error_chirho| AdmissionRejectChirho::AssetOpRoundingChirho { error_chirho })?;
    validate_asset_op_record_coordinate_chirho(asset_op_chirho, &candidate_chirho)?;
    if !matches!(&candidate_chirho.op_chirho, LedgerOpChirho::TransferChirho) {
        return Err(AdmissionRejectChirho::AssetOpRecordMismatchChirho {
            detail_chirho: "derived AssetOp must be absorbed by one TransferChirho record"
                .to_owned(),
        });
    }
    let credit_count_chirho = candidate_chirho
        .legs_chirho
        .iter()
        .filter(|leg_chirho| matches!(leg_chirho.delta_chirho, LegDeltaChirho::CreditChirho))
        .count();
    let debit_count_chirho = candidate_chirho
        .legs_chirho
        .iter()
        .filter(|leg_chirho| matches!(leg_chirho.delta_chirho, LegDeltaChirho::DebitChirho))
        .count();
    let split_delta_chirho = if credit_count_chirho >= 2 && debit_count_chirho == 1 {
        LegDeltaChirho::CreditChirho
    } else if debit_count_chirho >= 2 && credit_count_chirho == 1 {
        LegDeltaChirho::DebitChirho
    } else {
        return Err(AdmissionRejectChirho::AssetOpRecordMismatchChirho {
            detail_chirho:
                "derived AssetOp requires one whole leg and at least two same-side split legs"
                    .to_owned(),
        });
    };
    if !candidate_chirho.legs_chirho.iter().any(|leg_chirho| {
        leg_chirho.delta_chirho == split_delta_chirho
            && leg_chirho.amount_chirho == asset_op_chirho.amount_chirho
    }) {
        return Err(AdmissionRejectChirho::AssetOpRecordMismatchChirho {
            detail_chirho: "derived AssetOp amount does not name a split ledger leg".to_owned(),
        });
    }
    admit_chirho(context_chirho, candidate_chirho)
}

fn resolve_asset_op_policy_chirho(
    context_chirho: &AdmissionContextChirho<'_>,
    asset_op_chirho: &AssetOpChirho,
) -> Result<KindPolicyViewChirho, AdmissionRejectChirho> {
    let policy_chirho = context_chirho
        .kind_registry_chirho
        .resolve_chirho(&asset_op_chirho.kind_policy_ref_chirho)
        .into_current_chirho()?;
    if policy_chirho.kind_id_chirho != asset_op_chirho.kind_id_chirho {
        return Err(AdmissionRejectChirho::KindIdentityMismatchChirho);
    }
    Ok(policy_chirho)
}

fn validate_asset_op_record_coordinate_chirho(
    asset_op_chirho: &AssetOpChirho,
    candidate_chirho: &LedgerRecordChirho,
) -> Result<(), AdmissionRejectChirho> {
    if candidate_chirho.legs_chirho.is_empty() {
        return Err(AdmissionRejectChirho::AssetOpRecordMismatchChirho {
            detail_chirho: "AssetOp cannot admit a record without money legs".to_owned(),
        });
    }
    if candidate_chirho.legs_chirho.iter().any(|leg_chirho| {
        leg_chirho.account_chirho.kind_id_chirho != asset_op_chirho.kind_id_chirho
            || leg_chirho.kind_policy_ref_chirho != asset_op_chirho.kind_policy_ref_chirho
    }) {
        return Err(AdmissionRejectChirho::AssetOpRecordMismatchChirho {
            detail_chirho: "AssetOp kind or immutable policy ref does not match every ledger leg"
                .to_owned(),
        });
    }
    Ok(())
}

/// FULL admission (B's, and B's alone). Fail-closed at the FIRST violated law; a rejected candidate
/// issues no token, changes no state, appends nothing (this function owns no state to change).
pub fn admit_chirho(
    context_chirho: &AdmissionContextChirho<'_>,
    candidate_chirho: LedgerRecordChirho,
) -> Result<AdmittedRecordChirho, AdmissionRejectChirho> {
    // 1. Wire canonicality: a record that cannot canonically EMIT never admits (schema/version).
    if let Err(error_chirho) = canonical_ledger_record_line_chirho(&candidate_chirho) {
        return Err(AdmissionRejectChirho::WireChirho { error_chirho });
    }
    // 2. Journal fencing: seq / prev / epoch bind the candidate to the TRUE tail under the lock
    //    (F1's optimistic-CAS shape), and the record self-proves its lease (§11.5 lease-bound append).
    if candidate_chirho.seq_chirho != context_chirho.expected_seq_chirho {
        return Err(AdmissionRejectChirho::SeqMismatchChirho {
            expected_chirho: context_chirho.expected_seq_chirho,
            found_chirho: candidate_chirho.seq_chirho,
        });
    }
    if candidate_chirho.prev_chirho != *context_chirho.expected_prev_chirho {
        return Err(AdmissionRejectChirho::PrevMismatchChirho);
    }
    if candidate_chirho.epoch_chirho != context_chirho.current_epoch_chirho {
        return Err(AdmissionRejectChirho::EpochMismatchChirho {
            expected_chirho: context_chirho.current_epoch_chirho,
            found_chirho: candidate_chirho.epoch_chirho,
        });
    }
    // 3. Per-journal HLC strict monotonicity (lexicographic (physical_ms, logical), §11.1).
    if candidate_chirho.hlc_chirho <= *context_chirho.tail_hlc_chirho {
        return Err(AdmissionRejectChirho::HlcNotMonotoneChirho);
    }
    // 3b. The §11.5 anchor law: EXACTLY the expected anchor (Some on an epoch's first record,
    //     binding the pre-advance tail; None in steady state) — never caller-chosen.
    if candidate_chirho.anchor_chirho.as_ref() != context_chirho.expected_anchor_chirho {
        return Err(AdmissionRejectChirho::AnchorMismatchChirho);
    }
    // 4. Idempotency inside the W-law window: a duplicate is REFUSED here (replay semantics — return
    //    the ORIGINAL — are the append caller's, above admission).
    if context_chirho
        .recent_idempotency_keys_chirho
        .contains(&candidate_chirho.idempotency_key_chirho)
    {
        return Err(AdmissionRejectChirho::IdempotencyDuplicateChirho);
    }
    // 5. The INDEPENDENT §11.10 grammar (coded from the table, wildcard-free).
    classify_grammar_chirho(&candidate_chirho)?;
    // 6. R1 membership: EVERY touched account (credit AND debit legs — a non-member payee is as
    //    illegal as a non-member payer), at the record's epoch.
    for leg_chirho in &candidate_chirho.legs_chirho {
        match context_chirho
            .membership_chirho
            .status_chirho(&leg_chirho.account_chirho, candidate_chirho.epoch_chirho)
        {
            MembershipStatusChirho::MemberChirho => {}
            MembershipStatusChirho::RevokedChirho => {
                return Err(AdmissionRejectChirho::RevokedMemberChirho {
                    owner_chirho: leg_chirho.account_chirho.owner_chirho.clone(),
                })
            }
            MembershipStatusChirho::NonMemberChirho => {
                return Err(AdmissionRejectChirho::NonMemberChirho {
                    owner_chirho: leg_chirho.account_chirho.owner_chirho.clone(),
                })
            }
        }
    }
    // 7. R-KIND binding: resolve EVERY leg's policy revision through the registry and bind
    //    resolve(kind_policy_ref).kind_id == account.kind_id. There is deliberately NO
    //    resolved-kind annotation to trust — the registry is consulted per admission (RK.1-RK.3).
    let mut policy_by_ref_chirho: BTreeMap<AssetKindRefChirho, KindPolicyViewChirho> =
        BTreeMap::new();
    for leg_chirho in &candidate_chirho.legs_chirho {
        let policy_chirho = if let Some(policy_chirho) =
            policy_by_ref_chirho.get(&leg_chirho.kind_policy_ref_chirho)
        {
            policy_chirho.clone()
        } else {
            let policy_chirho = context_chirho
                .kind_registry_chirho
                .resolve_chirho(&leg_chirho.kind_policy_ref_chirho)
                .into_current_chirho()?;
            policy_by_ref_chirho.insert(
                leg_chirho.kind_policy_ref_chirho.clone(),
                policy_chirho.clone(),
            );
            policy_chirho
        };
        if policy_chirho.kind_id_chirho != leg_chirho.account_chirho.kind_id_chirho {
            return Err(AdmissionRejectChirho::KindIdentityMismatchChirho);
        }
    }
    let policy_refs_chirho: Vec<AssetKindRefChirho> =
        policy_by_ref_chirho.keys().cloned().collect();
    let retention_chirho = if policy_by_ref_chirho.is_empty()
        || policy_by_ref_chirho
            .values()
            .any(|policy_chirho| policy_chirho.idempotency_window_chirho.is_none())
    {
        IdempotencyRetentionChirho::LegacyUnprunedChirho { policy_refs_chirho }
    } else {
        let idempotency_horizon_ms_chirho = policy_by_ref_chirho
            .values()
            .filter_map(|policy_chirho| policy_chirho.idempotency_window_chirho)
            .map(|window_chirho| window_chirho.idempotency_horizon_ms_chirho)
            .max()
            .expect("nonempty all-bounded policy set has an idempotency horizon");
        let retry_finality_horizon_ms_chirho = policy_by_ref_chirho
            .values()
            .filter_map(|policy_chirho| policy_chirho.idempotency_window_chirho)
            .map(|window_chirho| window_chirho.retry_finality_horizon_ms_chirho)
            .max()
            .expect("nonempty all-bounded policy set has a retry/finality horizon");
        IdempotencyRetentionChirho::BoundedChirho {
            policy_refs_chirho,
            idempotency_horizon_ms_chirho,
            retry_finality_horizon_ms_chirho,
        }
    };
    // 8. R5a per-stable-kind conservation for Transfer (Σ=0 netted by account.kind_id — a Debit of
    //    X can never fund a Credit of Y; Mint/Burn are authorized value-in/out and exempt).
    if matches!(candidate_chirho.op_chirho, LedgerOpChirho::TransferChirho) {
        let mut net_by_kind_chirho: BTreeMap<&AssetKindIdChirho, i128> = BTreeMap::new();
        for leg_chirho in &candidate_chirho.legs_chirho {
            let entry_chirho = net_by_kind_chirho
                .entry(&leg_chirho.account_chirho.kind_id_chirho)
                .or_insert(0);
            let amount_chirho = i128::from(leg_chirho.amount_chirho);
            match leg_chirho.delta_chirho {
                LegDeltaChirho::CreditChirho => *entry_chirho += amount_chirho,
                LegDeltaChirho::DebitChirho => *entry_chirho -= amount_chirho,
                // Grammar admits only Credit/Debit on a Transfer; total match keeps this fold total.
                LegDeltaChirho::HoldChirho
                | LegDeltaChirho::ReleaseChirho
                | LegDeltaChirho::FinalizeChirho => {
                    return Err(AdmissionRejectChirho::BadShapeChirho {
                        detail_chirho: "non-credit/debit delta reached the conservation fold"
                            .to_owned(),
                    })
                }
            }
        }
        for (kind_id_chirho, net_chirho) in net_by_kind_chirho {
            if net_chirho != 0 {
                return Err(AdmissionRejectChirho::KindConservationChirho {
                    kind_id_chirho: kind_id_chirho.clone(),
                });
            }
        }
    }
    // 9. R2 authority + supply: mint/burn evidence is RESOLVED and must cover the minted/burned
    //    kind; a bounded platform kind enforces its cumulative cap with checked math; zero-amount
    //    mint/burn is REFUSED (R2.5 pinned strict: a 0-op may not be a silent supply-aggregate hole).
    match &candidate_chirho.op_chirho {
        LedgerOpChirho::MintChirho {
            authority_evidence_chirho,
        } => {
            let leg_chirho = &candidate_chirho.legs_chirho[0];
            if leg_chirho.amount_chirho == 0 {
                return Err(AdmissionRejectChirho::ZeroAmountMintChirho);
            }
            let kind_id_chirho = &leg_chirho.account_chirho.kind_id_chirho;
            // AUTHORITY GATES FIRST (claude2 #4526 defense-in-depth): an unauthorized caller
            // learns nothing about supply/cap state — the evidence verifies before any resource
            // state is consulted.
            match context_chirho
                .authority_chirho
                .verify_mint_chirho(authority_evidence_chirho, kind_id_chirho)
            {
                AuthorityVerdictChirho::VerifiedChirho => {}
                AuthorityVerdictChirho::UnverifiedChirho => {
                    return Err(AdmissionRejectChirho::MintAuthorityUnverifiedChirho)
                }
                AuthorityVerdictChirho::WrongKindChirho => {
                    return Err(AdmissionRejectChirho::MintAuthorityWrongKindChirho)
                }
            }
            let policy_chirho = context_chirho
                .kind_registry_chirho
                .resolve_chirho(&leg_chirho.kind_policy_ref_chirho)
                .into_current_chirho()?;
            // Supply-aggregate overflow is checked at admission for EVERY mint mode — uncapped
            // (`ProviderReceipt` / `PlatformPolicy{None}`) included (self-audit finding #1). Without
            // this, an uncapped mint that overflows the durable Σ-supply aggregate would pass
            // admission, get durably appended, THEN fail in the post-append `apply_supply_chirho`,
            // committing a record the engine can't reopen (the overflow re-trips on replay → a
            // bricked journal). Checking here makes the mint side of `apply_supply_chirho` LOCALLY
            // infallible: supply OVERFLOW is reachable (mint adds unboundedly), so it earns a hoisted
            // admission guard, and no admitted mint can fail to persist-and-reopen. Burn's underflow is
            // the asymmetric case — unreachable, guaranteed EMERGENTLY by the fence + conservation
            // rather than a local guard; see the burn arm below for why it carries no symmetric check.
            let current_supply_chirho = context_chirho
                .supply_by_kind_chirho
                .get(kind_id_chirho)
                .copied()
                .unwrap_or(0);
            let after_supply_chirho = current_supply_chirho
                .checked_add(leg_chirho.amount_chirho)
                .ok_or(AdmissionRejectChirho::ArithmeticChirho)?;
            match policy_chirho.mint_authority_chirho {
                MintAuthorityPolicyChirho::ClosedChirho => {
                    return Err(AdmissionRejectChirho::MintClosedKindChirho)
                }
                MintAuthorityPolicyChirho::ProviderReceiptChirho => {}
                MintAuthorityPolicyChirho::PlatformPolicyChirho { max_supply_chirho } => {
                    if let Some(max_supply_chirho) = max_supply_chirho {
                        if after_supply_chirho > max_supply_chirho {
                            return Err(AdmissionRejectChirho::SupplyCapExceededChirho);
                        }
                    }
                }
            }
        }
        LedgerOpChirho::BurnChirho {
            authority_evidence_chirho,
        } => {
            let leg_chirho = &candidate_chirho.legs_chirho[0];
            if leg_chirho.amount_chirho == 0 {
                return Err(AdmissionRejectChirho::ZeroAmountBurnChirho);
            }
            let kind_id_chirho = &leg_chirho.account_chirho.kind_id_chirho;
            match context_chirho
                .authority_chirho
                .verify_burn_chirho(authority_evidence_chirho, kind_id_chirho)
            {
                AuthorityVerdictChirho::VerifiedChirho => {}
                AuthorityVerdictChirho::UnverifiedChirho => {
                    return Err(AdmissionRejectChirho::BurnAuthorityUnverifiedChirho)
                }
                AuthorityVerdictChirho::WrongKindChirho => {
                    return Err(AdmissionRejectChirho::BurnAuthorityWrongKindChirho)
                }
            }
            // Deliberately NO hoisted supply-UNDERFLOW guard here — asymmetric with mint's overflow
            // guard, by design (claude2 #4590). Burn's post-append `apply_supply_chirho` does a
            // checked_sub on the Σ-supply aggregate, and its infallibility is EMERGENT, not local:
            // the F4 fence (step 10) forces the burning account's net ≥ amount, and supply == Σ(nets)
            // ≥ that net, so supply ≥ amount ALWAYS holds in a conserved store — the checked_sub can
            // never underflow. A hoisted check would be redundant with the fence (unreachable), and
            // the independent differential oracle rightly does not model it, so adding it would only
            // desync the two admission codings. The checked_sub is itself the fail-closed backstop: a
            // conservation-maintenance regression that broke the invariant surfaces as a ChainChirho
            // error on that record, never silent supply corruption. (Mint differs because supply
            // OVERFLOW is genuinely reachable — mint adds unboundedly — so it earns a local guard.)
        }
        LedgerOpChirho::TransferChirho
        | LedgerOpChirho::TimerChirho { .. }
        // The escrow family needs no mint/burn authority evidence; its own laws (the control
        // identity + holds index + settlement target) run at the escrow-law step below.
        | LedgerOpChirho::EscrowHoldChirho { .. }
        | LedgerOpChirho::EscrowFinalizeChirho { .. }
        | LedgerOpChirho::EscrowReleaseChirho { .. } => {}
        // Grammar (step 5) already refused everything else; keep the match total + wildcard-free.
        LedgerOpChirho::CreditChirho
        | LedgerOpChirho::DebitChirho
        | LedgerOpChirho::CompensationChirho { .. } => {
            return Err(AdmissionRejectChirho::UnsupportedOperationChirho)
        }
    }
    // 9b. The CF2 ESCROW LAWS (the R4 control identity made operational): Hold refuses a
    //     duplicate unconsumed key (the EXACT (account, saga, step) triple — P3); Release and
    //     Finalize require the EXACT five-way match (account, kind-via-account, amount, saga,
    //     step) against an UNCONSUMED hold; Finalize's Credit leg must target the kind's
    //     DESIGNATED settlement account from the CURRENT policy (sub-ruling a; None = refuse).
    //     Consumption itself is the journal's post-append/replay state transition — admission
    //     only ever READS the index (pure decision).
    match &candidate_chirho.op_chirho {
        LedgerOpChirho::EscrowHoldChirho { control_chirho } => {
            let leg_chirho = &candidate_chirho.legs_chirho[0];
            let key_chirho = EscrowHoldKeyChirho {
                account_chirho: leg_chirho.account_chirho.clone(),
                saga_id_chirho: control_chirho.saga_id_chirho.clone(),
                step_chirho: control_chirho.step_chirho,
            };
            if context_chirho.active_holds_chirho.contains_key(&key_chirho) {
                return Err(AdmissionRejectChirho::DuplicateEscrowHoldChirho);
            }
        }
        LedgerOpChirho::EscrowReleaseChirho { control_chirho }
        | LedgerOpChirho::EscrowFinalizeChirho { control_chirho } => {
            let leg_chirho = &candidate_chirho.legs_chirho[0];
            let key_chirho = EscrowHoldKeyChirho {
                account_chirho: leg_chirho.account_chirho.clone(),
                saga_id_chirho: control_chirho.saga_id_chirho.clone(),
                step_chirho: control_chirho.step_chirho,
            };
            match context_chirho.active_holds_chirho.get(&key_chirho) {
                Some(held_amount_chirho) if *held_amount_chirho == leg_chirho.amount_chirho => {}
                _ => return Err(AdmissionRejectChirho::UnknownEscrowHoldChirho),
            }
            if let LedgerOpChirho::EscrowFinalizeChirho { .. } = &candidate_chirho.op_chirho {
                let credit_chirho = &candidate_chirho.legs_chirho[1];
                let policy_chirho = context_chirho
                    .kind_registry_chirho
                    .resolve_chirho(&credit_chirho.kind_policy_ref_chirho)
                    .into_current_chirho()?;
                match policy_chirho.settlement_owner_chirho {
                    Some(settlement_owner_chirho)
                        if credit_chirho.account_chirho.owner_chirho == settlement_owner_chirho => {
                    }
                    _ => return Err(AdmissionRejectChirho::SettlementTargetMismatchChirho),
                }
            }
        }
        _ => {}
    }
    // 9c. The CF2 F3a X-CLUSTER LAWS (§11.8a — signed #5038/#5044/#5045/#5046): shape passed the
    //     grammar; here the AUTHORITY. Law v FIRST: absence of the composed finality views keeps
    //     the row ExplicitlyUnsupported — infrastructure absence never default-opens a money door.
    if matches!(candidate_chirho.op_chirho, LedgerOpChirho::TransferChirho)
        && candidate_chirho
            .legs_chirho
            .iter()
            .any(|leg_chirho| leg_chirho.counterpart_chirho.is_some())
    {
        let Some(views_chirho) = context_chirho.finality_chirho else {
            return Err(AdmissionRejectChirho::UnsupportedOperationChirho);
        };
        let credit_leg_chirho = &candidate_chirho.legs_chirho[1];
        let debit_leg_chirho = &candidate_chirho.legs_chirho[0];
        let claim_chirho = credit_leg_chirho
            .counterpart_chirho
            .as_ref()
            .expect("grammar guaranteed the claim on the credit leg");
        // Law (i) — BOUND, never referenced: resolve + re-hash + canonical parse + source sig.
        let Some(proof_bytes_chirho) = views_chirho
            .proofs_chirho
            .resolve_chirho(&claim_chirho.burn_chirho.finality_proof_ref_chirho)
        else {
            return Err(AdmissionRejectChirho::CounterpartProofMissingChirho);
        };
        let proof_text_chirho = std::str::from_utf8(&proof_bytes_chirho).map_err(|_| {
            AdmissionRejectChirho::CounterpartProofInvalidChirho {
                detail_chirho: "proof bytes are not UTF-8".to_owned(),
            }
        })?;
        let rehash_chirho = DigestChirho(
            blake3::hash(proof_bytes_chirho.as_slice())
                .to_hex()
                .to_string(),
        );
        if rehash_chirho != claim_chirho.burn_chirho.finality_proof_ref_chirho {
            return Err(AdmissionRejectChirho::CounterpartProofInvalidChirho {
                detail_chirho: "content address mismatch".to_owned(),
            });
        }
        let proof_chirho =
            cairn_ledger_model_chirho::finality_chirho::parse_canonical_finality_proof_line_chirho(
                proof_text_chirho,
            )
            .map_err(|error_chirho| {
                AdmissionRejectChirho::CounterpartProofInvalidChirho {
                    detail_chirho: format!("canonical parse: {error_chirho:?}"),
                }
            })?;
        let signed_content_chirho =
            cairn_ledger_model_chirho::finality_chirho::finality_proof_signed_content_chirho(
                &proof_chirho,
            )
            .map_err(|error_chirho| {
                AdmissionRejectChirho::CounterpartProofInvalidChirho {
                    detail_chirho: format!("signed content: {error_chirho:?}"),
                }
            })?;
        if !views_chirho.source_roots_chirho.verify_chirho(
            &claim_chirho.burn_chirho.source_money_group_chirho,
            &signed_content_chirho,
            &proof_chirho.root_sig_chirho,
        ) {
            return Err(AdmissionRejectChirho::CounterpartProofInvalidChirho {
                detail_chirho: "source root signature does not verify".to_owned(),
            });
        }
        if !proof_chirho.matches_burn_ref_chirho(&claim_chirho.burn_chirho) {
            return Err(AdmissionRejectChirho::CounterpartBindingMismatchChirho {
                detail_chirho: "proof locator diverges from the claim burn ref".to_owned(),
            });
        }
        if !proof_chirho.matches_claim_chirho(claim_chirho) {
            return Err(AdmissionRejectChirho::CounterpartBindingMismatchChirho {
                detail_chirho: "proof burn summary diverges from the claim".to_owned(),
            });
        }
        if claim_chirho.dst_chirho != credit_leg_chirho.account_chirho {
            return Err(AdmissionRejectChirho::CounterpartBindingMismatchChirho {
                detail_chirho: "claim dst is not the credit leg account".to_owned(),
            });
        }
        if claim_chirho.amount_chirho != credit_leg_chirho.amount_chirho {
            return Err(AdmissionRejectChirho::CounterpartBindingMismatchChirho {
                detail_chirho: "claim amount is not the credit leg amount".to_owned(),
            });
        }
        if claim_chirho.kind_policy_ref_chirho != credit_leg_chirho.kind_policy_ref_chirho {
            return Err(AdmissionRejectChirho::CounterpartBindingMismatchChirho {
                detail_chirho: "claim kind revision is not the credit leg revision".to_owned(),
            });
        }
        if debit_leg_chirho.account_chirho.kind_id_chirho
            != credit_leg_chirho.account_chirho.kind_id_chirho
        {
            return Err(AdmissionRejectChirho::CounterpartBindingMismatchChirho {
                detail_chirho: "a transfer never changes kind (src.kind != dst.kind)".to_owned(),
            });
        }
        if claim_chirho.dst_cluster_chirho != *context_chirho.cluster_chirho {
            return Err(AdmissionRejectChirho::CounterpartBindingMismatchChirho {
                detail_chirho: "claim dst_cluster is not THIS journal".to_owned(),
            });
        }
        // Law (ii) — consume-once: the nullifier is DERIVED, never chosen; first claim wins.
        if !claim_chirho.nullifier_is_bound_chirho() {
            return Err(AdmissionRejectChirho::CounterpartNullifierMismatchChirho);
        }
        if context_chirho
            .consumed_nullifiers_chirho
            .contains(&claim_chirho.nullifier_chirho)
        {
            return Err(AdmissionRejectChirho::CounterpartNullifierConsumedChirho);
        }
        // Law (iv) — the R3 role gate: verified settlement authorization, never self-declaration.
        if !views_chirho.settlement_authorizations_chirho.verify_chirho(
            &claim_chirho.transfer_id_chirho,
            &claim_chirho.channel_chirho,
            &debit_leg_chirho.account_chirho,
        ) {
            return Err(AdmissionRejectChirho::SettlementAuthorizationRefusedChirho);
        }
        // Law (iii) — finality: the cut law (cut_seq >= burn seq) held at canonical parse; the
        // source-root signature above IS the destination's finality authority. Production source
        // issuance remains absent until one verified snapshot binds both exact witnesses (§11.8a).
    }
    // 10. The F1/F4 fence: recompute EVERY leg's post from the TRUE current head (absent account =
    //     zero baseline), in leg order (record-internal same-account legs chain), with checked math
    //     and the spendable floor after every value-affecting fold. A precomputed post is NEVER
    //     trusted — two records prepared against one head cannot both land (the stale-credit trap).
    let mut working_chirho: BTreeMap<&AccountIdChirho, LegPostStateChirho> = BTreeMap::new();
    for (leg_index_chirho, leg_chirho) in candidate_chirho.legs_chirho.iter().enumerate() {
        let state_chirho = working_chirho
            .entry(&leg_chirho.account_chirho)
            .or_insert_with(|| {
                context_chirho
                    .head_states_chirho
                    .get(&leg_chirho.account_chirho)
                    .cloned()
                    .unwrap_or(LegPostStateChirho {
                        credits_total_chirho: 0,
                        debits_total_chirho: 0,
                        held_chirho: 0,
                    })
            });
        fold_leg_post_chirho(
            state_chirho,
            &leg_chirho.delta_chirho,
            leg_chirho.amount_chirho,
        )?;
        // F4 spendable floor — after every fold that can lower spendable (i128: no intermediate wrap).
        let spendable_chirho = i128::from(state_chirho.credits_total_chirho)
            - i128::from(state_chirho.debits_total_chirho)
            - i128::from(state_chirho.held_chirho);
        if spendable_chirho < 0 {
            return Err(AdmissionRejectChirho::SpendableFloorChirho { leg_index_chirho });
        }
        // F1 post-currency: the carried post must EQUAL the recomputed fold.
        if *state_chirho != leg_chirho.post_chirho {
            return Err(AdmissionRejectChirho::PostStateMismatchChirho { leg_index_chirho });
        }
    }
    Ok(AdmittedRecordChirho {
        record_chirho: candidate_chirho,
        retention_chirho,
    })
}

/// The ONE checked leg fold (Pr1 counter math): apply a delta to an account's running totals,
/// refusing on overflow/underflow — money never wraps. Shared by the ENGINE's record builder and
/// the admission fence (internal reuse is deliberate: a fold bug then diverges from the INDEPENDENT
/// reference oracle and the differential catches it — that is the differential's job).
pub(crate) fn fold_leg_post_chirho(
    state_chirho: &mut LegPostStateChirho,
    delta_chirho: &LegDeltaChirho,
    amount_chirho: u64,
) -> Result<(), AdmissionRejectChirho> {
    match delta_chirho {
        LegDeltaChirho::CreditChirho => {
            state_chirho.credits_total_chirho = state_chirho
                .credits_total_chirho
                .checked_add(amount_chirho)
                .ok_or(AdmissionRejectChirho::ArithmeticChirho)?;
        }
        LegDeltaChirho::DebitChirho => {
            state_chirho.debits_total_chirho = state_chirho
                .debits_total_chirho
                .checked_add(amount_chirho)
                .ok_or(AdmissionRejectChirho::ArithmeticChirho)?;
        }
        LegDeltaChirho::HoldChirho => {
            state_chirho.held_chirho = state_chirho
                .held_chirho
                .checked_add(amount_chirho)
                .ok_or(AdmissionRejectChirho::ArithmeticChirho)?;
        }
        LegDeltaChirho::ReleaseChirho => {
            state_chirho.held_chirho = state_chirho
                .held_chirho
                .checked_sub(amount_chirho)
                .ok_or(AdmissionRejectChirho::ArithmeticChirho)?;
        }
        LegDeltaChirho::FinalizeChirho => {
            state_chirho.held_chirho = state_chirho
                .held_chirho
                .checked_sub(amount_chirho)
                .ok_or(AdmissionRejectChirho::ArithmeticChirho)?;
            state_chirho.debits_total_chirho = state_chirho
                .debits_total_chirho
                .checked_add(amount_chirho)
                .ok_or(AdmissionRejectChirho::ArithmeticChirho)?;
        }
    }
    Ok(())
}

/// B's INDEPENDENT coding of the §11.10 op→leg grammar table — compile-exhaustive, wildcard-free
/// (a NEW `LedgerOpChirho` variant fails compilation until classified HERE), never shared with the
/// reference oracle's grammar (the independence law: a shared validator would let one grammar bug
/// pass the differential silently).
fn classify_grammar_chirho(
    candidate_chirho: &LedgerRecordChirho,
) -> Result<(), AdmissionRejectChirho> {
    let legs_chirho = &candidate_chirho.legs_chirho;
    let any_counterpart_chirho = legs_chirho
        .iter()
        .any(|leg_chirho: &LedgerLegChirho| leg_chirho.counterpart_chirho.is_some());
    match &candidate_chirho.op_chirho {
        LedgerOpChirho::TransferChirho => {
            // The §11.10 discriminator: ANY counterpart ⇒ the x-cluster settlement FORM. Its
            // SHAPE is validated here (CF2 F3a row: exactly [Debit settlement, Credit dst], the
            // ONE claim on the Credit leg); its AUTHORITY (laws i-iv) runs at step 9c, and a
            // journal composed WITHOUT the finality views refuses there as Unsupported (law v).
            if any_counterpart_chirho {
                if legs_chirho.len() != 2 {
                    return Err(AdmissionRejectChirho::BadShapeChirho {
                        detail_chirho:
                            "x-cluster settlement is exactly [Debit settlement, Credit dst]"
                                .to_owned(),
                    });
                }
                let debit_ok_chirho =
                    matches!(legs_chirho[0].delta_chirho, LegDeltaChirho::DebitChirho)
                        && legs_chirho[0].counterpart_chirho.is_none();
                let credit_ok_chirho =
                    matches!(legs_chirho[1].delta_chirho, LegDeltaChirho::CreditChirho)
                        && legs_chirho[1].counterpart_chirho.is_some();
                if !debit_ok_chirho || !credit_ok_chirho {
                    return Err(AdmissionRejectChirho::BadShapeChirho {
                        detail_chirho: "the ONE claim rides the Credit leg; the Debit leg is bare"
                            .to_owned(),
                    });
                }
                return Ok(());
            }
            if legs_chirho.len() < 2 {
                return Err(AdmissionRejectChirho::BadShapeChirho {
                    detail_chirho: "internal Transfer requires >= 2 balanced legs".to_owned(),
                });
            }
            for leg_chirho in legs_chirho {
                if !matches!(
                    leg_chirho.delta_chirho,
                    LegDeltaChirho::CreditChirho | LegDeltaChirho::DebitChirho
                ) {
                    return Err(AdmissionRejectChirho::BadShapeChirho {
                        detail_chirho: "Transfer legs are Credit/Debit only".to_owned(),
                    });
                }
            }
            Ok(())
        }
        LedgerOpChirho::MintChirho { .. } => {
            if legs_chirho.len() != 1
                || !matches!(legs_chirho[0].delta_chirho, LegDeltaChirho::CreditChirho)
            {
                return Err(AdmissionRejectChirho::BadShapeChirho {
                    detail_chirho: "Mint is exactly 1 Credit leg".to_owned(),
                });
            }
            if any_counterpart_chirho {
                return Err(AdmissionRejectChirho::BadShapeChirho {
                    detail_chirho: "a counterpart claim never rides a Mint".to_owned(),
                });
            }
            Ok(())
        }
        LedgerOpChirho::BurnChirho { .. } => {
            if legs_chirho.len() != 1
                || !matches!(legs_chirho[0].delta_chirho, LegDeltaChirho::DebitChirho)
            {
                return Err(AdmissionRejectChirho::BadShapeChirho {
                    detail_chirho: "Burn is exactly 1 Debit leg".to_owned(),
                });
            }
            if any_counterpart_chirho {
                return Err(AdmissionRejectChirho::BadShapeChirho {
                    detail_chirho: "a counterpart claim never rides a Burn".to_owned(),
                });
            }
            Ok(())
        }
        LedgerOpChirho::TimerChirho { .. } => {
            if !legs_chirho.is_empty() {
                return Err(AdmissionRejectChirho::BadShapeChirho {
                    detail_chirho: "Timer carries exactly zero money legs".to_owned(),
                });
            }
            Ok(())
        }
        LedgerOpChirho::EscrowHoldChirho { .. } => {
            // §11.10 CF2 row: exactly 1 Hold leg, counterpart Forbidden (the control identity is
            // structural — the op type carries it; dup-hold + the F4 floor run at their steps).
            if any_counterpart_chirho {
                return Err(AdmissionRejectChirho::BadShapeChirho {
                    detail_chirho: "EscrowHold forbids counterparts".to_owned(),
                });
            }
            match legs_chirho.as_slice() {
                [leg_chirho] if leg_chirho.delta_chirho == LegDeltaChirho::HoldChirho => Ok(()),
                _ => Err(AdmissionRejectChirho::BadShapeChirho {
                    detail_chirho: "EscrowHold requires exactly one Hold leg".to_owned(),
                }),
            }
        }
        LedgerOpChirho::EscrowReleaseChirho { .. } => {
            if any_counterpart_chirho {
                return Err(AdmissionRejectChirho::BadShapeChirho {
                    detail_chirho: "EscrowRelease forbids counterparts".to_owned(),
                });
            }
            match legs_chirho.as_slice() {
                [leg_chirho] if leg_chirho.delta_chirho == LegDeltaChirho::ReleaseChirho => Ok(()),
                _ => Err(AdmissionRejectChirho::BadShapeChirho {
                    detail_chirho: "EscrowRelease requires exactly one Release leg".to_owned(),
                }),
            }
        }
        LedgerOpChirho::EscrowFinalizeChirho { .. } => {
            // §11.10 CF2 row: exactly [Finalize, Credit→settlement], Σ=0 per stable kind (equal
            // amount, one kind); the settlement-target law runs at the escrow-law step.
            if any_counterpart_chirho {
                return Err(AdmissionRejectChirho::BadShapeChirho {
                    detail_chirho: "EscrowFinalize forbids counterparts".to_owned(),
                });
            }
            match legs_chirho.as_slice() {
                [finalize_chirho, credit_chirho]
                    if finalize_chirho.delta_chirho == LegDeltaChirho::FinalizeChirho
                        && credit_chirho.delta_chirho == LegDeltaChirho::CreditChirho =>
                {
                    if finalize_chirho.amount_chirho != credit_chirho.amount_chirho
                        || finalize_chirho.account_chirho.kind_id_chirho
                            != credit_chirho.account_chirho.kind_id_chirho
                    {
                        return Err(AdmissionRejectChirho::BadShapeChirho {
                            detail_chirho:
                                "EscrowFinalize legs must carry equal amount and one stable kind"
                                    .to_owned(),
                        });
                    }
                    Ok(())
                }
                _ => Err(AdmissionRejectChirho::BadShapeChirho {
                    detail_chirho: "EscrowFinalize requires exactly [Finalize, Credit] legs"
                        .to_owned(),
                }),
            }
        }
        LedgerOpChirho::CreditChirho
        | LedgerOpChirho::DebitChirho
        | LedgerOpChirho::CompensationChirho { .. } => {
            Err(AdmissionRejectChirho::UnsupportedOperationChirho)
        }
    }
}
