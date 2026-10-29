// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The two-seat DIFFERENTIAL, bound to B's real admitted-record token. Two independent money
//! checkers must agree: B's `admit_chirho` (membership + authority + registry + fence, `admission_chirho`)
//! and this crate's `apply_grammar_arithmetic_chirho` (the arithmetic/grammar/conservation oracle).
//!
//! - **Admission-only REDs** (the `ADMISSION-REDS-chirho.md` catalog): a record that is
//!   arithmetically/grammatically WELL-FORMED — so THIS oracle accepts its fold — but violates an
//!   authority the oracle structurally cannot see (membership, mint/burn authority, supply cap,
//!   kind-identity resolve). Each proves `admit_chirho` REJECTS on the intended dimension AND the
//!   oracle would have accepted — so the block is admission's, never an incidental arithmetic reject.
//! - **Boundary-form separation**: the oracle recognizes the amended counterpart Transfer grammar,
//!   while B still refuses without composed finality + settlement views. B's proof/nullifier/role
//!   authority is intentionally invisible here; the positive differential joins the two surfaces
//!   only after both independently landed implementations exist.
//! - **Positive re-entry**: an admitted record's carried posts equal the INDEPENDENT oracle's
//!   recomputed posts over the same pre-state — the arithmetic differential B's shared builder+fence
//!   fold is checked against (claude d50d2beb: a shared-fold bug diverges here).
//!
//! The stubs implement the PUBLIC view traits only (a second-seat fixture, independent of B's own
//! test scaffolding). Per the catalog non-goals these attack the WIRING — did admission call the
//! right verifier, on the right field, fail-closed — not the verifiers' own soundness (B's crypto REDs).

use crate::{RefLedgerChirho, RejectReasonChirho};
use cairn_ledger_log_chirho::admission_chirho::{
    admit_chirho, AdmissionContextChirho, AdmissionRejectChirho, AuthorityVerdictChirho,
    AuthorityVerifierViewChirho, EscrowHoldKeyChirho, KindPolicyViewChirho, KindRegistryViewChirho,
    KindResolutionChirho, MembershipStatusChirho, MembershipViewChirho, MintAuthorityPolicyChirho,
};
use cairn_ledger_model_chirho::asset_op_chirho::RoundingChirho;
use cairn_ledger_model_chirho::counterpart_chirho::CounterpartNullifierChirho;
use cairn_ledger_model_chirho::ids_chirho::{
    AccountIdChirho, AssetKindIdChirho, AssetKindRefChirho, ClusterIdChirho, DigestChirho,
    MoneyGroupIdChirho, SettlementChannelIdChirho, TransferIdChirho,
};
use cairn_ledger_model_chirho::record_chirho::{
    AttributionChirho, EscrowControlChirho, HlcChirho, LedgerLegChirho, LedgerOpChirho,
    LedgerRecordChirho, LegDeltaChirho, LegPostStateChirho,
};
use cairn_ledger_model_chirho::wire_chirho::LEDGER_RECORD_SCHEMA_V1_CHIRHO;
use cairn_ledger_model_chirho::{LogIdChirho, ShardEpochChirho};
use std::collections::{BTreeMap, BTreeSet};

// ---- names (a second-seat fixture, independent of B's) --------------------------------------------
const MONEY_KIND_CHIRHO: &str = "money-chirho";
const POINTS_KIND_CHIRHO: &str = "points-chirho";
const MONEY_REF_CHIRHO: &str = "policy-money-v1-chirho";
const POINTS_REF_CHIRHO: &str = "policy-points-v1-chirho";
/// Registered, but resolves to POINTS — the wrong-kind bait for a MONEY-account leg (RK.1/RK.3).
const WRONGKIND_REF_CHIRHO: &str = "policy-points-as-money-chirho";
/// Deliberately NOT in the registry (RK.2 fail-closed).
const UNREGISTERED_REF_CHIRHO: &str = "policy-unregistered-chirho";
const GOOD_MINT_EVIDENCE_CHIRHO: &str = "evidence-good-mint-chirho";
const WRONGKIND_MINT_EVIDENCE_CHIRHO: &str = "evidence-wrong-kind-chirho";
const GOOD_BURN_EVIDENCE_CHIRHO: &str = "evidence-good-burn-chirho";
const FORGED_EVIDENCE_CHIRHO: &str = "evidence-forged-chirho";

// ---- stubs over the PUBLIC view traits ------------------------------------------------------------

struct MembershipStubChirho {
    members_chirho: BTreeSet<String>,
    revoked_chirho: BTreeSet<String>,
}

impl MembershipViewChirho for MembershipStubChirho {
    fn status_chirho(
        &self,
        account_chirho: &AccountIdChirho,
        _epoch_chirho: ShardEpochChirho,
    ) -> MembershipStatusChirho {
        if self.revoked_chirho.contains(&account_chirho.owner_chirho) {
            MembershipStatusChirho::RevokedChirho
        } else if self.members_chirho.contains(&account_chirho.owner_chirho) {
            MembershipStatusChirho::MemberChirho
        } else {
            MembershipStatusChirho::NonMemberChirho
        }
    }
}

struct RegistryStubChirho {
    policies_chirho: BTreeMap<AssetKindRefChirho, KindPolicyViewChirho>,
}

impl KindRegistryViewChirho for RegistryStubChirho {
    fn resolve_chirho(&self, policy_ref_chirho: &AssetKindRefChirho) -> KindResolutionChirho {
        self.policies_chirho.get(policy_ref_chirho).cloned().map_or(
            KindResolutionChirho::UnknownChirho,
            KindResolutionChirho::CurrentChirho,
        )
    }
}

/// Fail-closed: unknown evidence is Unverified; only the exact blessed evidence for the exact kind
/// Verifies (attacks the wiring — a RED passes only by naming what the fixture blesses).
struct AuthorityStubChirho;

impl AuthorityVerifierViewChirho for AuthorityStubChirho {
    fn verify_mint_chirho(
        &self,
        evidence_chirho: &DigestChirho,
        kind_id_chirho: &AssetKindIdChirho,
    ) -> AuthorityVerdictChirho {
        match evidence_chirho.0.as_str() {
            GOOD_MINT_EVIDENCE_CHIRHO if kind_id_chirho.0 == MONEY_KIND_CHIRHO => {
                AuthorityVerdictChirho::VerifiedChirho
            }
            WRONGKIND_MINT_EVIDENCE_CHIRHO => AuthorityVerdictChirho::WrongKindChirho,
            _ => AuthorityVerdictChirho::UnverifiedChirho,
        }
    }

    fn verify_burn_chirho(
        &self,
        evidence_chirho: &DigestChirho,
        kind_id_chirho: &AssetKindIdChirho,
    ) -> AuthorityVerdictChirho {
        match evidence_chirho.0.as_str() {
            GOOD_BURN_EVIDENCE_CHIRHO if kind_id_chirho.0 == MONEY_KIND_CHIRHO => {
                AuthorityVerdictChirho::VerifiedChirho
            }
            _ => AuthorityVerdictChirho::UnverifiedChirho,
        }
    }
}

/// Owns everything the borrowed [`AdmissionContextChirho`] points at; tests mutate the public fields
/// (supply, head states, idempotency) before building the context.
struct FixtureChirho {
    membership_chirho: MembershipStubChirho,
    registry_chirho: RegistryStubChirho,
    authority_chirho: AuthorityStubChirho,
    prev_chirho: DigestChirho,
    tail_hlc_chirho: HlcChirho,
    head_states_chirho: BTreeMap<AccountIdChirho, LegPostStateChirho>,
    supply_by_kind_chirho: BTreeMap<AssetKindIdChirho, u64>,
    recent_idempotency_keys_chirho: BTreeSet<String>,
    active_holds_chirho: BTreeMap<EscrowHoldKeyChirho, u64>,
    consumed_nullifiers_chirho: BTreeSet<CounterpartNullifierChirho>,
    cluster_chirho: ClusterIdChirho,
}

impl FixtureChirho {
    fn new_chirho() -> Self {
        let mut policies_chirho = BTreeMap::new();
        policies_chirho.insert(
            kind_ref_chirho(MONEY_REF_CHIRHO),
            KindPolicyViewChirho {
                kind_id_chirho: AssetKindIdChirho(MONEY_KIND_CHIRHO.into()),
                mint_authority_chirho: MintAuthorityPolicyChirho::PlatformPolicyChirho {
                    max_supply_chirho: Some(1_000),
                },
                rounding_chirho: RoundingChirho::NearestTiesToEvenChirho,
                settlement_owner_chirho: None,
                idempotency_window_chirho: None,
            },
        );
        for ref_chirho in [POINTS_REF_CHIRHO, WRONGKIND_REF_CHIRHO] {
            // Both resolve to the POINTS stable id (WRONGKIND is a real, registered POINTS revision —
            // that is exactly what makes it a wrong-kind bait on a MONEY account, not an unknown ref).
            policies_chirho.insert(
                kind_ref_chirho(ref_chirho),
                KindPolicyViewChirho {
                    kind_id_chirho: AssetKindIdChirho(POINTS_KIND_CHIRHO.into()),
                    mint_authority_chirho: MintAuthorityPolicyChirho::PlatformPolicyChirho {
                        max_supply_chirho: None,
                    },
                    rounding_chirho: RoundingChirho::DownChirho,
                    settlement_owner_chirho: None,
                    idempotency_window_chirho: None,
                },
            );
        }
        let mut head_states_chirho = BTreeMap::new();
        head_states_chirho.insert(
            account_chirho("alice-chirho", MONEY_KIND_CHIRHO),
            post_chirho(100, 0, 0),
        );
        FixtureChirho {
            membership_chirho: MembershipStubChirho {
                members_chirho: [
                    "alice-chirho",
                    "bob-chirho",
                    "carol-chirho",
                    "issuer-chirho",
                ]
                .into_iter()
                .map(str::to_owned)
                .collect(),
                revoked_chirho: ["carol-revoked-chirho"]
                    .into_iter()
                    .map(str::to_owned)
                    .collect(),
            },
            registry_chirho: RegistryStubChirho { policies_chirho },
            authority_chirho: AuthorityStubChirho,
            prev_chirho: DigestChirho("tail-digest-chirho".into()),
            tail_hlc_chirho: HlcChirho {
                physical_ms_chirho: 900,
                logical_chirho: 0,
            },
            head_states_chirho,
            supply_by_kind_chirho: BTreeMap::new(),
            recent_idempotency_keys_chirho: BTreeSet::new(),
            active_holds_chirho: BTreeMap::new(),
            consumed_nullifiers_chirho: BTreeSet::new(),
            cluster_chirho: ClusterIdChirho("cluster-fixture-chirho".into()),
        }
    }

    fn context_chirho(&self) -> AdmissionContextChirho<'_> {
        AdmissionContextChirho {
            expected_seq_chirho: 1,
            expected_prev_chirho: &self.prev_chirho,
            current_epoch_chirho: 1,
            tail_hlc_chirho: &self.tail_hlc_chirho,
            membership_chirho: &self.membership_chirho,
            kind_registry_chirho: &self.registry_chirho,
            authority_chirho: &self.authority_chirho,
            head_states_chirho: &self.head_states_chirho,
            supply_by_kind_chirho: &self.supply_by_kind_chirho,
            recent_idempotency_keys_chirho: &self.recent_idempotency_keys_chirho,
            active_holds_chirho: &self.active_holds_chirho,
            cluster_chirho: &self.cluster_chirho,
            consumed_nullifiers_chirho: &self.consumed_nullifiers_chirho,
            finality_chirho: None,
            // §11.5 anchor law at admission (claude 4c68f785): steady-state (no epoch advance in any
            // of these vectors) requires NO anchor, and every record carries `anchor_chirho: None`.
            expected_anchor_chirho: None,
        }
    }
}

// ---- builders (mirror the frozen §11 wire so every record is canonical + admit-shaped) ------------

fn account_chirho(owner_chirho: &str, kind_chirho: &str) -> AccountIdChirho {
    LogIdChirho::new_chirho(owner_chirho, kind_chirho)
}

fn kind_ref_chirho(id_chirho: &str) -> AssetKindRefChirho {
    AssetKindRefChirho(DigestChirho(id_chirho.into()))
}

fn post_chirho(c_chirho: u64, d_chirho: u64, h_chirho: u64) -> LegPostStateChirho {
    LegPostStateChirho {
        credits_total_chirho: c_chirho,
        debits_total_chirho: d_chirho,
        held_chirho: h_chirho,
    }
}

#[allow(clippy::too_many_arguments)]
fn leg_chirho(
    owner_chirho: &str,
    kind_chirho: &str,
    policy_ref_chirho: &str,
    delta_chirho: LegDeltaChirho,
    amount_chirho: u64,
    post_chirho_arg: LegPostStateChirho,
) -> LedgerLegChirho {
    LedgerLegChirho {
        account_chirho: account_chirho(owner_chirho, kind_chirho),
        kind_policy_ref_chirho: kind_ref_chirho(policy_ref_chirho),
        delta_chirho,
        amount_chirho,
        post_chirho: post_chirho_arg,
        counterpart_chirho: None,
    }
}

fn record_chirho(
    op_chirho: LedgerOpChirho,
    legs_chirho: Vec<LedgerLegChirho>,
) -> LedgerRecordChirho {
    LedgerRecordChirho {
        schema_chirho: LEDGER_RECORD_SCHEMA_V1_CHIRHO.into(),
        format_version_chirho: 1,
        seq_chirho: 1,
        prev_chirho: DigestChirho("tail-digest-chirho".into()),
        epoch_chirho: 1,
        hlc_chirho: HlcChirho {
            physical_ms_chirho: 1_000,
            logical_chirho: 0,
        },
        legs_chirho,
        op_chirho,
        idempotency_key_chirho: "idem-1-chirho".into(),
        provenance_chirho: None,
        attribution_chirho: AttributionChirho::PlatformChirho,
        anchor_chirho: None,
        sig_chirho: "sig-chirho".into(),
        key_id_chirho: "key-chirho".into(),
    }
}

fn mint_op_chirho(evidence_chirho: &str) -> LedgerOpChirho {
    LedgerOpChirho::MintChirho {
        authority_evidence_chirho: DigestChirho(evidence_chirho.into()),
    }
}

fn burn_op_chirho(evidence_chirho: &str) -> LedgerOpChirho {
    LedgerOpChirho::BurnChirho {
        authority_evidence_chirho: DigestChirho(evidence_chirho.into()),
    }
}

// ---- the independent arithmetic oracle over the SAME pre-state ------------------------------------

/// A reference ledger seeded to a pre-state via 1-Credit mints (the oracle lazily opens at zero, so
/// a seed IS a mint). This is the oracle's view of admission's `head_states`.
fn seeded_oracle_chirho(seeds_chirho: &[(&str, &str, u64)]) -> RefLedgerChirho {
    let mut oracle_chirho = RefLedgerChirho::new_chirho();
    for (owner_chirho, kind_chirho, amount_chirho) in seeds_chirho {
        let legs_chirho = vec![leg_chirho(
            owner_chirho,
            kind_chirho,
            MONEY_REF_CHIRHO,
            LegDeltaChirho::CreditChirho,
            *amount_chirho,
            post_chirho(*amount_chirho, 0, 0),
        )];
        oracle_chirho
            .apply_grammar_arithmetic_chirho(&legs_chirho, &mint_op_chirho("seed-chirho"))
            .expect("seed mint folds");
    }
    oracle_chirho
}

/// Assert the independent oracle ACCEPTS this record's fold over `seeds` (so the record is
/// arithmetically well-formed and any admission reject is authority's, not arithmetic's).
fn assert_oracle_accepts_chirho(
    seeds_chirho: &[(&str, &str, u64)],
    record_chirho: &LedgerRecordChirho,
) {
    let mut oracle_chirho = seeded_oracle_chirho(seeds_chirho);
    let recomputed_chirho = oracle_chirho
        .apply_grammar_arithmetic_chirho(&record_chirho.legs_chirho, &record_chirho.op_chirho)
        .expect("oracle accepts the (arithmetically valid) record admission rejects on authority");
    let carried_chirho: Vec<LegPostStateChirho> = record_chirho
        .legs_chirho
        .iter()
        .map(|leg_chirho| leg_chirho.post_chirho.clone())
        .collect();
    assert_eq!(
        recomputed_chirho, carried_chirho,
        "independent oracle posts must equal the record's carried posts"
    );
}

// ==== R1 — membership (the oracle opens any account lazily at zero, so a non-member is invisible) ===

#[test]
fn r1_1_credit_to_non_member_is_refused_chirho() {
    let fixture_chirho = FixtureChirho::new_chirho();
    // alice(member, 100) pays mallory(NON-member) 40 — balanced, posts correct, spendable>=0.
    let record_chirho = record_chirho(
        LedgerOpChirho::TransferChirho,
        vec![
            leg_chirho(
                "alice-chirho",
                MONEY_KIND_CHIRHO,
                MONEY_REF_CHIRHO,
                LegDeltaChirho::DebitChirho,
                40,
                post_chirho(100, 40, 0),
            ),
            leg_chirho(
                "mallory-chirho",
                MONEY_KIND_CHIRHO,
                MONEY_REF_CHIRHO,
                LegDeltaChirho::CreditChirho,
                40,
                post_chirho(40, 0, 0),
            ),
        ],
    );
    // The oracle (which can't see membership) ACCEPTS: the block is admission's.
    assert_oracle_accepts_chirho(&[("alice-chirho", MONEY_KIND_CHIRHO, 100)], &record_chirho);
    assert_eq!(
        admit_chirho(&fixture_chirho.context_chirho(), record_chirho),
        Err(AdmissionRejectChirho::NonMemberChirho {
            owner_chirho: "mallory-chirho".into(),
        }),
        "a non-member PAYEE still receives spendable money — credit legs must be checked too"
    );
}

#[test]
fn r1_2_debit_from_non_member_is_refused_chirho() {
    let mut fixture_chirho = FixtureChirho::new_chirho();
    // A non-member with a lazily-opened zero baseline can't be overdrawn (never funded), so arithmetic
    // passes — only membership catches it. Fund mallory's oracle baseline so the fold is valid.
    fixture_chirho.head_states_chirho.insert(
        account_chirho("mallory-chirho", MONEY_KIND_CHIRHO),
        post_chirho(100, 0, 0),
    );
    let record_chirho = record_chirho(
        LedgerOpChirho::TransferChirho,
        vec![
            leg_chirho(
                "mallory-chirho",
                MONEY_KIND_CHIRHO,
                MONEY_REF_CHIRHO,
                LegDeltaChirho::DebitChirho,
                40,
                post_chirho(100, 40, 0),
            ),
            leg_chirho(
                "bob-chirho",
                MONEY_KIND_CHIRHO,
                MONEY_REF_CHIRHO,
                LegDeltaChirho::CreditChirho,
                40,
                post_chirho(40, 0, 0),
            ),
        ],
    );
    assert_oracle_accepts_chirho(
        &[("mallory-chirho", MONEY_KIND_CHIRHO, 100)],
        &record_chirho,
    );
    assert_eq!(
        admit_chirho(&fixture_chirho.context_chirho(), record_chirho),
        Err(AdmissionRejectChirho::NonMemberChirho {
            owner_chirho: "mallory-chirho".into(),
        })
    );
}

#[test]
fn r1_3_mint_into_non_member_is_refused_chirho() {
    let fixture_chirho = FixtureChirho::new_chirho();
    // Authorized mint (GOOD evidence) but the DESTINATION is unmanaged — authority is not enough.
    let record_chirho = record_chirho(
        mint_op_chirho(GOOD_MINT_EVIDENCE_CHIRHO),
        vec![leg_chirho(
            "mallory-chirho",
            MONEY_KIND_CHIRHO,
            MONEY_REF_CHIRHO,
            LegDeltaChirho::CreditChirho,
            1_000_000,
            post_chirho(1_000_000, 0, 0),
        )],
    );
    assert_oracle_accepts_chirho(&[], &record_chirho);
    assert_eq!(
        admit_chirho(&fixture_chirho.context_chirho(), record_chirho),
        Err(AdmissionRejectChirho::NonMemberChirho {
            owner_chirho: "mallory-chirho".into(),
        })
    );
}

#[test]
fn r1_4_revoked_member_is_refused_chirho() {
    let mut fixture_chirho = FixtureChirho::new_chirho();
    fixture_chirho.head_states_chirho.insert(
        account_chirho("carol-revoked-chirho", MONEY_KIND_CHIRHO),
        post_chirho(100, 0, 0),
    );
    let record_chirho = record_chirho(
        LedgerOpChirho::TransferChirho,
        vec![
            leg_chirho(
                "carol-revoked-chirho",
                MONEY_KIND_CHIRHO,
                MONEY_REF_CHIRHO,
                LegDeltaChirho::DebitChirho,
                40,
                post_chirho(100, 40, 0),
            ),
            leg_chirho(
                "bob-chirho",
                MONEY_KIND_CHIRHO,
                MONEY_REF_CHIRHO,
                LegDeltaChirho::CreditChirho,
                40,
                post_chirho(40, 0, 0),
            ),
        ],
    );
    assert_oracle_accepts_chirho(
        &[("carol-revoked-chirho", MONEY_KIND_CHIRHO, 100)],
        &record_chirho,
    );
    assert_eq!(
        admit_chirho(&fixture_chirho.context_chirho(), record_chirho),
        Err(AdmissionRejectChirho::RevokedMemberChirho {
            owner_chirho: "carol-revoked-chirho".into(),
        })
    );
}

// ==== R2 — mint/burn authority + supply (the oracle accepts the SHAPE; only B verifies evidence) ===

#[test]
fn r2_1_forged_mint_evidence_is_refused_chirho() {
    let fixture_chirho = FixtureChirho::new_chirho();
    // A non-empty authority_evidence that resolves to no grant — presence is never sufficiency.
    let record_chirho = record_chirho(
        mint_op_chirho(FORGED_EVIDENCE_CHIRHO),
        vec![leg_chirho(
            "issuer-chirho",
            MONEY_KIND_CHIRHO,
            MONEY_REF_CHIRHO,
            LegDeltaChirho::CreditChirho,
            500,
            post_chirho(500, 0, 0),
        )],
    );
    assert_oracle_accepts_chirho(&[], &record_chirho);
    assert_eq!(
        admit_chirho(&fixture_chirho.context_chirho(), record_chirho),
        Err(AdmissionRejectChirho::MintAuthorityUnverifiedChirho)
    );
}

#[test]
fn r2_2_wrong_kind_mint_authority_is_refused_chirho() {
    let fixture_chirho = FixtureChirho::new_chirho();
    // Evidence a verifier recognizes, but whose grant does not cover the minted kind.
    let record_chirho = record_chirho(
        mint_op_chirho(WRONGKIND_MINT_EVIDENCE_CHIRHO),
        vec![leg_chirho(
            "issuer-chirho",
            MONEY_KIND_CHIRHO,
            MONEY_REF_CHIRHO,
            LegDeltaChirho::CreditChirho,
            100,
            post_chirho(100, 0, 0),
        )],
    );
    assert_oracle_accepts_chirho(&[], &record_chirho);
    assert_eq!(
        admit_chirho(&fixture_chirho.context_chirho(), record_chirho),
        Err(AdmissionRejectChirho::MintAuthorityWrongKindChirho)
    );
}

#[test]
fn r2_3_over_cap_mint_is_refused_chirho() {
    let mut fixture_chirho = FixtureChirho::new_chirho();
    // Each mint is individually authorized; the cumulative SUM breaches max_supply(1000).
    fixture_chirho
        .supply_by_kind_chirho
        .insert(AssetKindIdChirho(MONEY_KIND_CHIRHO.into()), 950);
    let record_chirho = record_chirho(
        mint_op_chirho(GOOD_MINT_EVIDENCE_CHIRHO),
        vec![leg_chirho(
            "issuer-chirho",
            MONEY_KIND_CHIRHO,
            MONEY_REF_CHIRHO,
            LegDeltaChirho::CreditChirho,
            100,
            post_chirho(100, 0, 0),
        )],
    );
    assert_oracle_accepts_chirho(&[], &record_chirho);
    assert_eq!(
        admit_chirho(&fixture_chirho.context_chirho(), record_chirho),
        Err(AdmissionRejectChirho::SupplyCapExceededChirho)
    );
}

#[test]
fn r2_4_forged_burn_evidence_is_refused_chirho() {
    let fixture_chirho = FixtureChirho::new_chirho();
    // A valid-looking debit that keeps spendable>=0 — only authority separates a burn from theft.
    let record_chirho = record_chirho(
        burn_op_chirho(FORGED_EVIDENCE_CHIRHO),
        vec![leg_chirho(
            "alice-chirho",
            MONEY_KIND_CHIRHO,
            MONEY_REF_CHIRHO,
            LegDeltaChirho::DebitChirho,
            30,
            post_chirho(100, 30, 0),
        )],
    );
    assert_oracle_accepts_chirho(&[("alice-chirho", MONEY_KIND_CHIRHO, 100)], &record_chirho);
    assert_eq!(
        admit_chirho(&fixture_chirho.context_chirho(), record_chirho),
        Err(AdmissionRejectChirho::BurnAuthorityUnverifiedChirho)
    );
}

#[test]
fn r2_5_zero_amount_mint_is_refused_strict_chirho() {
    let fixture_chirho = FixtureChirho::new_chirho();
    // A 0-mint is arithmetically a no-op the oracle accepts; B pins it STRICT-refused (R2.5) so it can
    // never become a silent slot in the supply aggregate.
    let record_chirho = record_chirho(
        mint_op_chirho(GOOD_MINT_EVIDENCE_CHIRHO),
        vec![leg_chirho(
            "issuer-chirho",
            MONEY_KIND_CHIRHO,
            MONEY_REF_CHIRHO,
            LegDeltaChirho::CreditChirho,
            0,
            post_chirho(0, 0, 0),
        )],
    );
    assert_oracle_accepts_chirho(&[], &record_chirho);
    assert_eq!(
        admit_chirho(&fixture_chirho.context_chirho(), record_chirho),
        Err(AdmissionRejectChirho::ZeroAmountMintChirho)
    );
}

// ==== R-KIND — kind-identity resolve (a REGISTRY act the arithmetic oracle structurally lacks) =====

#[test]
fn rk_1_debit_leg_policy_ref_resolves_to_wrong_kind_chirho() {
    let fixture_chirho = FixtureChirho::new_chirho();
    // alice's MONEY account, but the debit leg cites a POINTS policy revision. The oracle keys
    // conservation by account.kind_id (money) so it balances; only the registry resolve catches it.
    let record_chirho = record_chirho(
        LedgerOpChirho::TransferChirho,
        vec![
            leg_chirho(
                "alice-chirho",
                MONEY_KIND_CHIRHO,
                WRONGKIND_REF_CHIRHO,
                LegDeltaChirho::DebitChirho,
                40,
                post_chirho(100, 40, 0),
            ),
            leg_chirho(
                "bob-chirho",
                MONEY_KIND_CHIRHO,
                MONEY_REF_CHIRHO,
                LegDeltaChirho::CreditChirho,
                40,
                post_chirho(40, 0, 0),
            ),
        ],
    );
    assert_oracle_accepts_chirho(&[("alice-chirho", MONEY_KIND_CHIRHO, 100)], &record_chirho);
    assert_eq!(
        admit_chirho(&fixture_chirho.context_chirho(), record_chirho),
        Err(AdmissionRejectChirho::KindIdentityMismatchChirho)
    );
}

#[test]
fn rk_2_unregistered_policy_ref_is_refused_fail_closed_chirho() {
    let fixture_chirho = FixtureChirho::new_chirho();
    let record_chirho = record_chirho(
        LedgerOpChirho::TransferChirho,
        vec![
            leg_chirho(
                "alice-chirho",
                MONEY_KIND_CHIRHO,
                UNREGISTERED_REF_CHIRHO,
                LegDeltaChirho::DebitChirho,
                40,
                post_chirho(100, 40, 0),
            ),
            leg_chirho(
                "bob-chirho",
                MONEY_KIND_CHIRHO,
                MONEY_REF_CHIRHO,
                LegDeltaChirho::CreditChirho,
                40,
                post_chirho(40, 0, 0),
            ),
        ],
    );
    assert_oracle_accepts_chirho(&[("alice-chirho", MONEY_KIND_CHIRHO, 100)], &record_chirho);
    assert_eq!(
        admit_chirho(&fixture_chirho.context_chirho(), record_chirho),
        Err(AdmissionRejectChirho::UnknownKindPolicyChirho)
    );
}

#[test]
fn rk_3_credit_leg_policy_ref_re_points_identity_chirho() {
    let fixture_chirho = FixtureChirho::new_chirho();
    // The CREDIT leg carries the wrong-kind revision — proving R-KIND checks credit legs too (a
    // revision may change policy, NEVER the stable identity an account is bound to).
    let record_chirho = record_chirho(
        LedgerOpChirho::TransferChirho,
        vec![
            leg_chirho(
                "alice-chirho",
                MONEY_KIND_CHIRHO,
                MONEY_REF_CHIRHO,
                LegDeltaChirho::DebitChirho,
                40,
                post_chirho(100, 40, 0),
            ),
            leg_chirho(
                "bob-chirho",
                MONEY_KIND_CHIRHO,
                WRONGKIND_REF_CHIRHO,
                LegDeltaChirho::CreditChirho,
                40,
                post_chirho(40, 0, 0),
            ),
        ],
    );
    assert_oracle_accepts_chirho(&[("alice-chirho", MONEY_KIND_CHIRHO, 100)], &record_chirho);
    assert_eq!(
        admit_chirho(&fixture_chirho.context_chirho(), record_chirho),
        Err(AdmissionRejectChirho::KindIdentityMismatchChirho)
    );
}

// ==== positive differential re-entry — admitted record's posts == the INDEPENDENT oracle's =========

#[test]
fn positive_transfer_admits_and_oracle_agrees_chirho() {
    let fixture_chirho = FixtureChirho::new_chirho();
    let record_chirho = record_chirho(
        LedgerOpChirho::TransferChirho,
        vec![
            leg_chirho(
                "alice-chirho",
                MONEY_KIND_CHIRHO,
                MONEY_REF_CHIRHO,
                LegDeltaChirho::DebitChirho,
                40,
                post_chirho(100, 40, 0),
            ),
            leg_chirho(
                "bob-chirho",
                MONEY_KIND_CHIRHO,
                MONEY_REF_CHIRHO,
                LegDeltaChirho::CreditChirho,
                40,
                post_chirho(40, 0, 0),
            ),
        ],
    );
    // Independent oracle over the SAME pre-state agrees on every post...
    assert_oracle_accepts_chirho(&[("alice-chirho", MONEY_KIND_CHIRHO, 100)], &record_chirho);
    // ...and B's admission issues the log-owned token. Two independent folds, one verdict.
    let token_chirho = admit_chirho(&fixture_chirho.context_chirho(), record_chirho.clone())
        .expect("admission issues the token");
    assert_eq!(token_chirho.record_chirho(), &record_chirho);
    // Final state is conserved: A + B == the original 100.
    let mut oracle_chirho = seeded_oracle_chirho(&[("alice-chirho", MONEY_KIND_CHIRHO, 100)]);
    oracle_chirho
        .apply_grammar_arithmetic_chirho(&record_chirho.legs_chirho, &record_chirho.op_chirho)
        .unwrap();
    assert_eq!(
        oracle_chirho
            .state_chirho(&account_chirho("alice-chirho", MONEY_KIND_CHIRHO))
            .net_money_chirho(),
        60
    );
    assert_eq!(
        oracle_chirho
            .state_chirho(&account_chirho("bob-chirho", MONEY_KIND_CHIRHO))
            .net_money_chirho(),
        40
    );
}

#[test]
fn positive_mint_admits_and_oracle_agrees_chirho() {
    let fixture_chirho = FixtureChirho::new_chirho();
    let record_chirho = record_chirho(
        mint_op_chirho(GOOD_MINT_EVIDENCE_CHIRHO),
        vec![leg_chirho(
            "issuer-chirho",
            MONEY_KIND_CHIRHO,
            MONEY_REF_CHIRHO,
            LegDeltaChirho::CreditChirho,
            250,
            post_chirho(250, 0, 0),
        )],
    );
    assert_oracle_accepts_chirho(&[], &record_chirho);
    admit_chirho(&fixture_chirho.context_chirho(), record_chirho)
        .expect("authorized under-cap mint admits");
}

#[test]
fn positive_burn_admits_and_oracle_agrees_chirho() {
    let fixture_chirho = FixtureChirho::new_chirho();
    let record_chirho = record_chirho(
        burn_op_chirho(GOOD_BURN_EVIDENCE_CHIRHO),
        vec![leg_chirho(
            "alice-chirho",
            MONEY_KIND_CHIRHO,
            MONEY_REF_CHIRHO,
            LegDeltaChirho::DebitChirho,
            30,
            post_chirho(100, 30, 0),
        )],
    );
    assert_oracle_accepts_chirho(&[("alice-chirho", MONEY_KIND_CHIRHO, 100)], &record_chirho);
    admit_chirho(&fixture_chirho.context_chirho(), record_chirho)
        .expect("authorized funded burn admits");
}

#[test]
fn positive_three_party_split_admits_and_oracle_agrees_chirho() {
    // A >=2-leg split (Debit 100 -> Credit 60 + Credit 40): the shared builder+fence fold must agree
    // with the independent oracle on EVERY leg's post, not just the canonical two-leg case.
    let fixture_chirho = FixtureChirho::new_chirho();
    let record_chirho = record_chirho(
        LedgerOpChirho::TransferChirho,
        vec![
            leg_chirho(
                "alice-chirho",
                MONEY_KIND_CHIRHO,
                MONEY_REF_CHIRHO,
                LegDeltaChirho::DebitChirho,
                100,
                post_chirho(100, 100, 0),
            ),
            leg_chirho(
                "bob-chirho",
                MONEY_KIND_CHIRHO,
                MONEY_REF_CHIRHO,
                LegDeltaChirho::CreditChirho,
                60,
                post_chirho(60, 0, 0),
            ),
            leg_chirho(
                "carol-chirho",
                MONEY_KIND_CHIRHO,
                MONEY_REF_CHIRHO,
                LegDeltaChirho::CreditChirho,
                40,
                post_chirho(40, 0, 0),
            ),
        ],
    );
    assert_oracle_accepts_chirho(&[("alice-chirho", MONEY_KIND_CHIRHO, 100)], &record_chirho);
    admit_chirho(&fixture_chirho.context_chirho(), record_chirho).expect("3-party split admits");
}

#[test]
fn positive_same_account_chain_admits_and_oracle_agrees_chirho() {
    // Two legs on ONE account fold SERIALLY (leg 2 chains from leg 1's post): the batch-order law both
    // folds must implement identically, or the carried post diverges from one of them.
    let fixture_chirho = FixtureChirho::new_chirho();
    let record_chirho = record_chirho(
        LedgerOpChirho::TransferChirho,
        vec![
            leg_chirho(
                "alice-chirho",
                MONEY_KIND_CHIRHO,
                MONEY_REF_CHIRHO,
                LegDeltaChirho::DebitChirho,
                60,
                post_chirho(100, 60, 0),
            ),
            leg_chirho(
                "alice-chirho",
                MONEY_KIND_CHIRHO,
                MONEY_REF_CHIRHO,
                LegDeltaChirho::CreditChirho,
                20,
                post_chirho(120, 60, 0),
            ),
            leg_chirho(
                "bob-chirho",
                MONEY_KIND_CHIRHO,
                MONEY_REF_CHIRHO,
                LegDeltaChirho::CreditChirho,
                40,
                post_chirho(40, 0, 0),
            ),
        ],
    );
    assert_oracle_accepts_chirho(&[("alice-chirho", MONEY_KIND_CHIRHO, 100)], &record_chirho);
    admit_chirho(&fixture_chirho.context_chirho(), record_chirho)
        .expect("same-account-chain transfer admits");
}

#[test]
fn positive_near_u64_transfer_admits_and_oracle_agrees_chirho() {
    // Near-ceiling amounts: both the checked builder+fence fold and the i128 oracle must move the value
    // EXACTLY — no wrap, no precision loss — or the posts diverge.
    let big_chirho = u64::MAX - 1000;
    let mut fixture_chirho = FixtureChirho::new_chirho();
    fixture_chirho.head_states_chirho.insert(
        account_chirho("alice-chirho", MONEY_KIND_CHIRHO),
        post_chirho(big_chirho, 0, 0),
    );
    let record_chirho = record_chirho(
        LedgerOpChirho::TransferChirho,
        vec![
            leg_chirho(
                "alice-chirho",
                MONEY_KIND_CHIRHO,
                MONEY_REF_CHIRHO,
                LegDeltaChirho::DebitChirho,
                big_chirho,
                post_chirho(big_chirho, big_chirho, 0),
            ),
            leg_chirho(
                "bob-chirho",
                MONEY_KIND_CHIRHO,
                MONEY_REF_CHIRHO,
                LegDeltaChirho::CreditChirho,
                big_chirho,
                post_chirho(big_chirho, 0, 0),
            ),
        ],
    );
    assert_oracle_accepts_chirho(
        &[("alice-chirho", MONEY_KIND_CHIRHO, big_chirho)],
        &record_chirho,
    );
    admit_chirho(&fixture_chirho.context_chirho(), record_chirho)
        .expect("near-u64 transfer admits");
}

// ==== shared-dimension REJECTION agreement — both independently-coded money checkers refuse the SAME
//      ill-formed record. My reference's arithmetic REDs (tests_chirho.rs) and B's admission REDs run
//      in PARALLEL, each over its own checker; here they meet on one input, so a divergence (one
//      accepts what the other rejects) is caught. The reject NAMES differ (independently coded); the
//      DIMENSION must agree. =============================================================================

/// Assert BOTH the independent oracle (seeded to `seeds`) and B's admission REJECT `record` — the
/// oracle on `oracle_reason`, admission on `admission_reason`. Two checkers, one ill-formed input.
fn assert_both_reject_chirho(
    fixture_chirho: &FixtureChirho,
    seeds_chirho: &[(&str, &str, u64)],
    record_chirho: LedgerRecordChirho,
    oracle_reason_chirho: RejectReasonChirho,
    admission_reason_chirho: AdmissionRejectChirho,
) {
    let mut oracle_chirho = seeded_oracle_chirho(seeds_chirho);
    assert_eq!(
        oracle_chirho
            .apply_grammar_arithmetic_chirho(&record_chirho.legs_chirho, &record_chirho.op_chirho),
        Err(oracle_reason_chirho),
        "the independent oracle must reject on its dimension"
    );
    assert_eq!(
        admit_chirho(&fixture_chirho.context_chirho(), record_chirho),
        Err(admission_reason_chirho),
        "B admission must reject the SAME record"
    );
}

#[test]
fn differential_unbalanced_transfer_both_reject_chirho() {
    // Debit 40 / Credit 30 -> Σ = -10 for the kind. Oracle: NotBalanced; admission: KindConservation.
    let fixture_chirho = FixtureChirho::new_chirho();
    let record_chirho = record_chirho(
        LedgerOpChirho::TransferChirho,
        vec![
            leg_chirho(
                "alice-chirho",
                MONEY_KIND_CHIRHO,
                MONEY_REF_CHIRHO,
                LegDeltaChirho::DebitChirho,
                40,
                post_chirho(100, 40, 0),
            ),
            leg_chirho(
                "bob-chirho",
                MONEY_KIND_CHIRHO,
                MONEY_REF_CHIRHO,
                LegDeltaChirho::CreditChirho,
                30,
                post_chirho(30, 0, 0),
            ),
        ],
    );
    assert_both_reject_chirho(
        &fixture_chirho,
        &[("alice-chirho", MONEY_KIND_CHIRHO, 100)],
        record_chirho,
        RejectReasonChirho::NotBalancedChirho,
        AdmissionRejectChirho::KindConservationChirho {
            kind_id_chirho: AssetKindIdChirho(MONEY_KIND_CHIRHO.into()),
        },
    );
}

#[test]
fn differential_overdraft_both_reject_chirho() {
    // Balanced (Debit 150 / Credit 150) but alice (funded 100) overdraws. Oracle: Overdraft;
    // admission: SpendableFloor on leg 0. Same dimension (spendable floor), independently named.
    let fixture_chirho = FixtureChirho::new_chirho();
    let record_chirho = record_chirho(
        LedgerOpChirho::TransferChirho,
        vec![
            leg_chirho(
                "alice-chirho",
                MONEY_KIND_CHIRHO,
                MONEY_REF_CHIRHO,
                LegDeltaChirho::DebitChirho,
                150,
                post_chirho(100, 150, 0),
            ),
            leg_chirho(
                "bob-chirho",
                MONEY_KIND_CHIRHO,
                MONEY_REF_CHIRHO,
                LegDeltaChirho::CreditChirho,
                150,
                post_chirho(150, 0, 0),
            ),
        ],
    );
    assert_both_reject_chirho(
        &fixture_chirho,
        &[("alice-chirho", MONEY_KIND_CHIRHO, 100)],
        record_chirho,
        RejectReasonChirho::OverdraftChirho,
        AdmissionRejectChirho::SpendableFloorChirho {
            leg_index_chirho: 0,
        },
    );
}

#[test]
fn differential_forged_post_both_reject_chirho() {
    // A balanced transfer whose CREDIT leg carries a forged (too-high) post. Oracle: PostMismatch;
    // admission: PostStateMismatch on leg 1. Neither trusts the carried post; both recompute.
    let fixture_chirho = FixtureChirho::new_chirho();
    let record_chirho = record_chirho(
        LedgerOpChirho::TransferChirho,
        vec![
            leg_chirho(
                "alice-chirho",
                MONEY_KIND_CHIRHO,
                MONEY_REF_CHIRHO,
                LegDeltaChirho::DebitChirho,
                40,
                post_chirho(100, 40, 0),
            ),
            leg_chirho(
                "bob-chirho",
                MONEY_KIND_CHIRHO,
                MONEY_REF_CHIRHO,
                LegDeltaChirho::CreditChirho,
                40,
                post_chirho(999, 0, 0),
            ),
        ],
    );
    assert_both_reject_chirho(
        &fixture_chirho,
        &[("alice-chirho", MONEY_KIND_CHIRHO, 100)],
        record_chirho,
        RejectReasonChirho::PostMismatchChirho,
        AdmissionRejectChirho::PostStateMismatchChirho {
            leg_index_chirho: 1,
        },
    );
}

#[test]
fn differential_cross_kind_transfer_both_reject_chirho() {
    // Debit money 40 / Credit POINTS 40: total nets zero but per-kind mints points, burns money.
    // Oracle: NotBalanced; admission: KindConservation (money sorts first). Both key by stable kind_id.
    let fixture_chirho = FixtureChirho::new_chirho();
    let record_chirho = record_chirho(
        LedgerOpChirho::TransferChirho,
        vec![
            leg_chirho(
                "alice-chirho",
                MONEY_KIND_CHIRHO,
                MONEY_REF_CHIRHO,
                LegDeltaChirho::DebitChirho,
                40,
                post_chirho(100, 40, 0),
            ),
            leg_chirho(
                "bob-chirho",
                POINTS_KIND_CHIRHO,
                POINTS_REF_CHIRHO,
                LegDeltaChirho::CreditChirho,
                40,
                post_chirho(40, 0, 0),
            ),
        ],
    );
    assert_both_reject_chirho(
        &fixture_chirho,
        &[("alice-chirho", MONEY_KIND_CHIRHO, 100)],
        record_chirho,
        RejectReasonChirho::NotBalancedChirho,
        AdmissionRejectChirho::KindConservationChirho {
            kind_id_chirho: AssetKindIdChirho(MONEY_KIND_CHIRHO.into()),
        },
    );
}

#[test]
fn differential_credit_overflow_both_reject_chirho() {
    // A balanced transfer whose credit would overflow bob's near-ceiling counter. Oracle: Arithmetic;
    // admission: Arithmetic. Checked math on both sides -- money never wraps to manufacture value.
    let mut fixture_chirho = FixtureChirho::new_chirho();
    fixture_chirho.head_states_chirho.insert(
        account_chirho("bob-chirho", MONEY_KIND_CHIRHO),
        post_chirho(u64::MAX - 5, 0, 0),
    );
    let record_chirho = record_chirho(
        LedgerOpChirho::TransferChirho,
        vec![
            leg_chirho(
                "alice-chirho",
                MONEY_KIND_CHIRHO,
                MONEY_REF_CHIRHO,
                LegDeltaChirho::DebitChirho,
                10,
                post_chirho(100, 10, 0),
            ),
            leg_chirho(
                "bob-chirho",
                MONEY_KIND_CHIRHO,
                MONEY_REF_CHIRHO,
                LegDeltaChirho::CreditChirho,
                10,
                // Dummy: the checked fold overflows and rejects before the post is ever compared.
                post_chirho(0, 0, 0),
            ),
        ],
    );
    assert_both_reject_chirho(
        &fixture_chirho,
        &[
            ("alice-chirho", MONEY_KIND_CHIRHO, 100),
            ("bob-chirho", MONEY_KIND_CHIRHO, u64::MAX - 5),
        ],
        record_chirho,
        RejectReasonChirho::ArithmeticChirho,
        AdmissionRejectChirho::ArithmeticChirho,
    );
}

// ==== positive escrow differential — the oracle folds the FULL lifecycle, B admits the tail ========

fn escrow_control_chirho(step_chirho: u32) -> EscrowControlChirho {
    EscrowControlChirho {
        saga_id_chirho: DigestChirho("saga-diff-chirho".into()),
        step_chirho,
    }
}

fn seeded_hold_fixture_chirho() -> FixtureChirho {
    let mut fixture_chirho = FixtureChirho::new_chirho();
    fixture_chirho.head_states_chirho.insert(
        account_chirho("alice-chirho", MONEY_KIND_CHIRHO),
        post_chirho(100, 0, 10),
    );
    fixture_chirho.active_holds_chirho.insert(
        EscrowHoldKeyChirho {
            account_chirho: account_chirho("alice-chirho", MONEY_KIND_CHIRHO),
            saga_id_chirho: DigestChirho("saga-diff-chirho".into()),
            step_chirho: 1,
        },
        10,
    );
    fixture_chirho
}

fn hold_record_chirho() -> LedgerRecordChirho {
    record_chirho(
        LedgerOpChirho::EscrowHoldChirho {
            control_chirho: escrow_control_chirho(1),
        },
        vec![leg_chirho(
            "alice-chirho",
            MONEY_KIND_CHIRHO,
            MONEY_REF_CHIRHO,
            LegDeltaChirho::HoldChirho,
            10,
            post_chirho(100, 0, 10),
        )],
    )
}

#[test]
fn positive_escrow_hold_admits_and_oracle_agrees_chirho() {
    let fixture_chirho = FixtureChirho::new_chirho();
    let record_chirho = hold_record_chirho();
    // The independent oracle folds the hold over the same pre-state and agrees on the post...
    assert_oracle_accepts_chirho(&[("alice-chirho", MONEY_KIND_CHIRHO, 100)], &record_chirho);
    // ...and B admits it as a FRESH key over an empty index.
    admit_chirho(&fixture_chirho.context_chirho(), record_chirho)
        .expect("a canonical fresh hold admits");
}

#[test]
fn positive_escrow_release_admits_and_oracle_agrees_chirho() {
    // Oracle path: seed 100 -> apply hold -> apply release (its OWN running fold carries the held
    // state B's context seeds directly — two roads to the same pre-state).
    let release_chirho = record_chirho(
        LedgerOpChirho::EscrowReleaseChirho {
            control_chirho: escrow_control_chirho(1),
        },
        vec![leg_chirho(
            "alice-chirho",
            MONEY_KIND_CHIRHO,
            MONEY_REF_CHIRHO,
            LegDeltaChirho::ReleaseChirho,
            10,
            post_chirho(100, 0, 0),
        )],
    );
    let mut oracle_chirho = seeded_oracle_chirho(&[("alice-chirho", MONEY_KIND_CHIRHO, 100)]);
    let hold_chirho = hold_record_chirho();
    oracle_chirho
        .apply_grammar_arithmetic_chirho(&hold_chirho.legs_chirho, &hold_chirho.op_chirho)
        .expect("oracle folds the hold");
    let posts_chirho = oracle_chirho
        .apply_grammar_arithmetic_chirho(&release_chirho.legs_chirho, &release_chirho.op_chirho)
        .expect("oracle folds the release");
    assert_eq!(
        posts_chirho,
        release_chirho
            .legs_chirho
            .iter()
            .map(|leg_chirho| leg_chirho.post_chirho.clone())
            .collect::<Vec<_>>(),
        "independent oracle posts must equal the record's carried posts"
    );
    assert_eq!(
        oracle_chirho
            .state_chirho(&account_chirho("alice-chirho", MONEY_KIND_CHIRHO))
            .spendable_chirho(),
        100,
        "a released hold returns every unit to spendable"
    );
    admit_chirho(
        &seeded_hold_fixture_chirho().context_chirho(),
        release_chirho,
    )
    .expect("the exact-match release admits over the seeded index");
}

#[test]
fn positive_escrow_finalize_admits_and_oracle_agrees_chirho() {
    let finalize_chirho = record_chirho(
        LedgerOpChirho::EscrowFinalizeChirho {
            control_chirho: escrow_control_chirho(1),
        },
        vec![
            leg_chirho(
                "alice-chirho",
                MONEY_KIND_CHIRHO,
                MONEY_REF_CHIRHO,
                LegDeltaChirho::FinalizeChirho,
                10,
                post_chirho(100, 10, 0),
            ),
            leg_chirho(
                "bob-chirho",
                MONEY_KIND_CHIRHO,
                MONEY_REF_CHIRHO,
                LegDeltaChirho::CreditChirho,
                10,
                post_chirho(10, 0, 0),
            ),
        ],
    );
    let mut oracle_chirho = seeded_oracle_chirho(&[("alice-chirho", MONEY_KIND_CHIRHO, 100)]);
    let hold_chirho = hold_record_chirho();
    oracle_chirho
        .apply_grammar_arithmetic_chirho(&hold_chirho.legs_chirho, &hold_chirho.op_chirho)
        .expect("oracle folds the hold");
    let posts_chirho = oracle_chirho
        .apply_grammar_arithmetic_chirho(&finalize_chirho.legs_chirho, &finalize_chirho.op_chirho)
        .expect("oracle folds the finalize (NetZero per kind)");
    assert_eq!(
        posts_chirho,
        finalize_chirho
            .legs_chirho
            .iter()
            .map(|leg_chirho| leg_chirho.post_chirho.clone())
            .collect::<Vec<_>>(),
        "independent oracle posts must equal the record's carried posts"
    );
    // Conservation across the settlement: alice 90 + bob 10 == the original 100.
    assert_eq!(
        oracle_chirho
            .state_chirho(&account_chirho("alice-chirho", MONEY_KIND_CHIRHO))
            .net_money_chirho()
            + oracle_chirho
                .state_chirho(&account_chirho("bob-chirho", MONEY_KIND_CHIRHO))
                .net_money_chirho(),
        100,
        "finalize conserves: held value SETTLES, it is never created or destroyed"
    );
    // B admits only with the DESIGNATED settlement account on the current policy.
    let mut fixture_chirho = seeded_hold_fixture_chirho();
    fixture_chirho
        .registry_chirho
        .policies_chirho
        .get_mut(&kind_ref_chirho(MONEY_REF_CHIRHO))
        .unwrap()
        .settlement_owner_chirho = Some("bob-chirho".to_owned());
    admit_chirho(&fixture_chirho.context_chirho(), finalize_chirho)
        .expect("finalize to the designated settlement account admits");
}

// ==== F3a positive differential — both landed surfaces joined (oracle e136a3af + B 3929765b) =====

#[test]
fn positive_x_cluster_claim_admits_and_oracle_agrees_chirho() {
    use cairn_ledger_log_chirho::admission_chirho::{
        FinalityAdmissionViewsChirho, FinalityProofBytesViewChirho,
        SettlementAuthorizationViewChirho, SourceRootVerifyViewChirho,
    };
    use cairn_ledger_model_chirho::counterpart_chirho::CounterpartNullifierChirho;
    use cairn_ledger_model_chirho::finality_chirho::{
        canonical_finality_proof_line_chirho, derive_finality_proof_ref_chirho,
        finality_proof_signed_content_chirho, FinalityProofChirho, RetainedCutChirho,
        FINALITY_PROOF_SCHEMA_V1_CHIRHO,
    };
    use cairn_ledger_model_chirho::ids_chirho::{
        MoneyGroupIdChirho, SettlementChannelIdChirho, TransferIdChirho,
    };
    // The valid signed proof + bound claim (B-side evidence).
    let mut proof_chirho = FinalityProofChirho {
        schema_chirho: FINALITY_PROOF_SCHEMA_V1_CHIRHO.into(),
        source_money_group_chirho: MoneyGroupIdChirho("mg-1-chirho".into()),
        source_cluster_chirho: ClusterIdChirho("cluster-src-chirho".into()),
        source_epoch_chirho: 1,
        source_seq_chirho: 7,
        source_record_digest_chirho: DigestChirho("burn-digest-chirho".into()),
        cut_chirho: RetainedCutChirho {
            cut_epoch_chirho: 1,
            cut_seq_chirho: 9,
            cut_record_digest_chirho: DigestChirho("cut-digest-chirho".into()),
        },
        burn_amount_chirho: 40,
        burn_kind_policy_ref_chirho: kind_ref_chirho(MONEY_REF_CHIRHO),
        burn_src_chirho: account_chirho("carol-chirho", MONEY_KIND_CHIRHO),
        burn_dst_money_group_chirho: MoneyGroupIdChirho("mg-1-chirho".into()),
        burn_dst_cluster_chirho: ClusterIdChirho("cluster-fixture-chirho".into()),
        burn_dst_chirho: account_chirho("bob-chirho", MONEY_KIND_CHIRHO),
        burn_channel_chirho: SettlementChannelIdChirho("chan-1-chirho".into()),
        root_sig_chirho: String::new(),
    };
    let _ = finality_proof_signed_content_chirho(&proof_chirho).unwrap();
    proof_chirho.root_sig_chirho = "mg-root-sig-fixture-chirho".to_owned();
    let proof_ref_chirho = derive_finality_proof_ref_chirho(&proof_chirho).unwrap();
    let proof_line_chirho = canonical_finality_proof_line_chirho(&proof_chirho).unwrap();

    struct OneProofChirho(DigestChirho, Vec<u8>);
    impl FinalityProofBytesViewChirho for OneProofChirho {
        fn resolve_chirho(&self, proof_ref_chirho: &DigestChirho) -> Option<Vec<u8>> {
            (proof_ref_chirho == &self.0).then(|| self.1.clone())
        }
    }
    struct MgRootChirho;
    impl SourceRootVerifyViewChirho for MgRootChirho {
        fn verify_chirho(
            &self,
            money_group_chirho: &MoneyGroupIdChirho,
            signed_content_chirho: &str,
            sig_chirho: &str,
        ) -> bool {
            // The crypto binding is admission-side law (proven in ledger-log); the differential
            // needs only a consistent predicate over the fixture sig.
            let _ = signed_content_chirho;
            money_group_chirho.0 == "mg-1-chirho" && sig_chirho == "mg-root-sig-fixture-chirho"
        }
    }
    struct OneAuthChirho;
    impl SettlementAuthorizationViewChirho for OneAuthChirho {
        fn verify_chirho(
            &self,
            transfer_id_chirho: &TransferIdChirho,
            channel_chirho: &SettlementChannelIdChirho,
            settlement_account_chirho: &AccountIdChirho,
        ) -> bool {
            transfer_id_chirho.0 == "t-pos-chirho"
                && channel_chirho.0 == "chan-1-chirho"
                && settlement_account_chirho.owner_chirho == "settlement-b-chirho"
        }
    }
    let proofs_chirho = OneProofChirho(proof_ref_chirho.clone(), proof_line_chirho.into_bytes());
    let roots_chirho = MgRootChirho;
    let auth_chirho = OneAuthChirho;

    let mut fixture_chirho = FixtureChirho::new_chirho();
    fixture_chirho
        .membership_chirho
        .members_chirho
        .insert("settlement-b-chirho".to_owned());
    fixture_chirho.head_states_chirho.insert(
        account_chirho("settlement-b-chirho", MONEY_KIND_CHIRHO),
        post_chirho(100, 0, 0),
    );
    let claim_chirho = cairn_ledger_model_chirho::counterpart_chirho::CounterpartClaimChirho {
        transfer_id_chirho: TransferIdChirho("t-pos-chirho".into()),
        burn_chirho: cairn_ledger_model_chirho::counterpart_chirho::FinalBurnRefChirho {
            source_money_group_chirho: proof_chirho.source_money_group_chirho.clone(),
            source_cluster_chirho: proof_chirho.source_cluster_chirho.clone(),
            source_epoch_chirho: proof_chirho.source_epoch_chirho,
            source_seq_chirho: proof_chirho.source_seq_chirho,
            source_record_digest_chirho: proof_chirho.source_record_digest_chirho.clone(),
            finality_proof_ref_chirho: proof_ref_chirho,
        },
        amount_chirho: 40,
        kind_policy_ref_chirho: proof_chirho.burn_kind_policy_ref_chirho.clone(),
        src_chirho: proof_chirho.burn_src_chirho.clone(),
        dst_money_group_chirho: proof_chirho.burn_dst_money_group_chirho.clone(),
        dst_cluster_chirho: proof_chirho.burn_dst_cluster_chirho.clone(),
        dst_chirho: proof_chirho.burn_dst_chirho.clone(),
        channel_chirho: proof_chirho.burn_channel_chirho.clone(),
        nullifier_chirho: CounterpartNullifierChirho::derive_chirho(
            &proof_chirho.source_money_group_chirho,
            &proof_chirho.source_cluster_chirho,
            proof_chirho.source_epoch_chirho,
            proof_chirho.source_seq_chirho,
            &proof_chirho.source_record_digest_chirho,
            &proof_chirho.burn_dst_money_group_chirho,
            &proof_chirho.burn_dst_cluster_chirho,
            &proof_chirho.burn_dst_chirho,
            &proof_chirho.burn_channel_chirho,
        ),
    };
    let mut record_chirho = record_chirho(
        LedgerOpChirho::TransferChirho,
        vec![
            leg_chirho(
                "settlement-b-chirho",
                MONEY_KIND_CHIRHO,
                MONEY_REF_CHIRHO,
                LegDeltaChirho::DebitChirho,
                40,
                post_chirho(100, 40, 0),
            ),
            leg_chirho(
                "bob-chirho",
                MONEY_KIND_CHIRHO,
                MONEY_REF_CHIRHO,
                LegDeltaChirho::CreditChirho,
                40,
                post_chirho(40, 0, 0),
            ),
        ],
    );
    record_chirho.legs_chirho[1].counterpart_chirho = Some(claim_chirho);
    // The INDEPENDENT oracle accepts the amended-table shape over the same pre-state...
    assert_oracle_accepts_chirho(
        &[("settlement-b-chirho", MONEY_KIND_CHIRHO, 100)],
        &record_chirho,
    );
    // ...and B admits it under the FULL evidence law with composed views (laws i-iv).
    let mut context_chirho = fixture_chirho.context_chirho();
    context_chirho.finality_chirho = Some(FinalityAdmissionViewsChirho {
        proofs_chirho: &proofs_chirho,
        source_roots_chirho: &roots_chirho,
        settlement_authorizations_chirho: &auth_chirho,
    });
    admit_chirho(&context_chirho, record_chirho)
        .expect("both independent surfaces admit the evidenced x-cluster credit");
}

mod counterpart_absence_chirho;
