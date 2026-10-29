// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! B-1 admission REDs — the in-crate half of the two-seat catalog: wiring proofs that every
//! admission dimension fires ON ITS OWN DIMENSION (a missing authority check can never hide behind
//! an incidental arithmetic reject), plus the positive token paths. claude2's second-seat vectors
//! (ADMISSION-REDS-chirho.md) bind against the exported token via dev-dependency when he wires them;
//! these tests are B's own adversarial floor.

use crate::admission_chirho::*;
use cairn_ledger_model_chirho::asset_op_chirho::{AssetOpChirho, RoundingChirho};
use cairn_ledger_model_chirho::counterpart_chirho::CounterpartNullifierChirho;
use cairn_ledger_model_chirho::ids_chirho::*;
use cairn_ledger_model_chirho::record_chirho::*;
use cairn_ledger_model_chirho::wire_chirho::LEDGER_RECORD_SCHEMA_V1_CHIRHO;
use cairn_ledger_model_chirho::{LogIdChirho, ShardEpochChirho};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) const MONEY_KIND_CHIRHO: &str = "money-chirho";
const POINTS_KIND_CHIRHO: &str = "points-chirho";
pub(crate) const MONEY_POLICY_REF_CHIRHO: &str = "policy-money-v1-chirho";
const POINTS_POLICY_REF_CHIRHO: &str = "policy-points-v1-chirho";
const WRONGKIND_POLICY_REF_CHIRHO: &str = "policy-points-as-money-chirho";
const CLOSED_KIND_CHIRHO: &str = "closed-kind-chirho";
const CLOSED_POLICY_REF_CHIRHO: &str = "policy-closed-v1-chirho";
const GOOD_MINT_EVIDENCE_CHIRHO: &str = "evidence-good-mint-chirho";
const WRONGKIND_EVIDENCE_CHIRHO: &str = "evidence-wrong-kind-chirho";
const GOOD_BURN_EVIDENCE_CHIRHO: &str = "evidence-good-burn-chirho";

pub(crate) struct StubMembershipChirho {
    pub(crate) members_chirho: BTreeSet<String>,
    revoked_chirho: BTreeSet<String>,
}

impl MembershipViewChirho for StubMembershipChirho {
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

pub(crate) struct StubRegistryChirho {
    pub(crate) policies_chirho: BTreeMap<AssetKindRefChirho, KindPolicyViewChirho>,
    superseded_chirho: BTreeSet<AssetKindRefChirho>,
}

impl KindRegistryViewChirho for StubRegistryChirho {
    fn resolve_chirho(&self, policy_ref_chirho: &AssetKindRefChirho) -> KindResolutionChirho {
        if self.superseded_chirho.contains(policy_ref_chirho) {
            return KindResolutionChirho::SupersededChirho;
        }
        self.policies_chirho.get(policy_ref_chirho).cloned().map_or(
            KindResolutionChirho::UnknownChirho,
            KindResolutionChirho::CurrentChirho,
        )
    }
}

/// Fail-closed stub: UNKNOWN evidence is Unverified by default — a RED can only pass by naming the
/// exact evidence the fixture blesses (attacks the wiring, per the catalog's non-goals).
pub(crate) struct StubAuthorityChirho;

impl AuthorityVerifierViewChirho for StubAuthorityChirho {
    fn verify_mint_chirho(
        &self,
        evidence_chirho: &DigestChirho,
        kind_id_chirho: &AssetKindIdChirho,
    ) -> AuthorityVerdictChirho {
        match evidence_chirho.0.as_str() {
            // The grant covers money AND the closed kind — so the closed-kind RED proves the
            // POLICY gate fires even when authority verifies (authority first, then policy).
            GOOD_MINT_EVIDENCE_CHIRHO
                if kind_id_chirho.0 == MONEY_KIND_CHIRHO
                    || kind_id_chirho.0 == CLOSED_KIND_CHIRHO =>
            {
                AuthorityVerdictChirho::VerifiedChirho
            }
            WRONGKIND_EVIDENCE_CHIRHO => AuthorityVerdictChirho::WrongKindChirho,
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

pub(crate) struct FixtureChirho {
    pub(crate) membership_chirho: StubMembershipChirho,
    pub(crate) registry_chirho: StubRegistryChirho,
    pub(crate) authority_chirho: StubAuthorityChirho,
    prev_chirho: DigestChirho,
    tail_hlc_chirho: HlcChirho,
    pub(crate) head_states_chirho: BTreeMap<AccountIdChirho, LegPostStateChirho>,
    supply_by_kind_chirho: BTreeMap<AssetKindIdChirho, u64>,
    recent_idempotency_keys_chirho: BTreeSet<String>,
    pub(crate) active_holds_chirho: BTreeMap<EscrowHoldKeyChirho, u64>,
    pub(crate) consumed_nullifiers_chirho: BTreeSet<CounterpartNullifierChirho>,
    pub(crate) finality_stubs_chirho: Option<FinalityStubsChirho>,
    cluster_chirho: ClusterIdChirho,
}

/// Fixture-owned stub views the context borrows when composed (law v: None = the row refuses).
pub(crate) struct FinalityStubsChirho {
    pub(crate) proofs_chirho: StubProofStoreChirho,
    pub(crate) roots_chirho: StubSourceRootsChirho,
    pub(crate) authorizations_chirho: StubSettlementAuthChirho,
}

#[derive(Default)]
pub(crate) struct StubProofStoreChirho {
    pub(crate) proofs_chirho: BTreeMap<DigestChirho, Vec<u8>>,
}

impl FinalityProofBytesViewChirho for StubProofStoreChirho {
    fn resolve_chirho(&self, proof_ref_chirho: &DigestChirho) -> Option<Vec<u8>> {
        self.proofs_chirho.get(proof_ref_chirho).cloned()
    }
}

/// Verifies the mg-root fake scheme for ONE money group only (wrong-group = wrong root).
pub(crate) struct StubSourceRootsChirho {
    pub(crate) money_group_chirho: String,
}

impl SourceRootVerifyViewChirho for StubSourceRootsChirho {
    fn verify_chirho(
        &self,
        money_group_chirho: &MoneyGroupIdChirho,
        signed_content_chirho: &str,
        sig_chirho: &str,
    ) -> bool {
        money_group_chirho.0 == self.money_group_chirho
            && sig_chirho
                == format!(
                    "mg-root-sig-{}",
                    &blake3::hash(signed_content_chirho.as_bytes()).to_hex()[..16]
                )
    }
}

/// Authorizes exactly one (transfer, channel, settlement-account) triple.
pub(crate) struct StubSettlementAuthChirho {
    pub(crate) transfer_chirho: String,
    pub(crate) channel_chirho: String,
    pub(crate) settlement_owner_chirho: String,
}

impl SettlementAuthorizationViewChirho for StubSettlementAuthChirho {
    fn verify_chirho(
        &self,
        transfer_id_chirho: &TransferIdChirho,
        channel_chirho: &SettlementChannelIdChirho,
        settlement_account_chirho: &AccountIdChirho,
    ) -> bool {
        transfer_id_chirho.0 == self.transfer_chirho
            && channel_chirho.0 == self.channel_chirho
            && settlement_account_chirho.owner_chirho == self.settlement_owner_chirho
    }
}

pub(crate) fn account_chirho(owner_chirho: &str, kind_chirho: &str) -> AccountIdChirho {
    LogIdChirho::new_chirho(owner_chirho, kind_chirho)
}

pub(crate) fn post_chirho(c_chirho: u64, d_chirho: u64, h_chirho: u64) -> LegPostStateChirho {
    LegPostStateChirho {
        credits_total_chirho: c_chirho,
        debits_total_chirho: d_chirho,
        held_chirho: h_chirho,
    }
}

impl FixtureChirho {
    pub(crate) fn new_chirho() -> Self {
        let mut policies_chirho = BTreeMap::new();
        policies_chirho.insert(
            AssetKindRefChirho(DigestChirho(MONEY_POLICY_REF_CHIRHO.into())),
            KindPolicyViewChirho {
                kind_id_chirho: MONEY_KIND_CHIRHO.into(),
                mint_authority_chirho: MintAuthorityPolicyChirho::PlatformPolicyChirho {
                    max_supply_chirho: Some(1_000),
                },
                rounding_chirho: RoundingChirho::NearestTiesToEvenChirho,
                settlement_owner_chirho: None,
                idempotency_window_chirho: None,
            },
        );
        policies_chirho.insert(
            AssetKindRefChirho(DigestChirho(POINTS_POLICY_REF_CHIRHO.into())),
            KindPolicyViewChirho {
                kind_id_chirho: POINTS_KIND_CHIRHO.into(),
                mint_authority_chirho: MintAuthorityPolicyChirho::PlatformPolicyChirho {
                    max_supply_chirho: None,
                },
                rounding_chirho: RoundingChirho::DownChirho,
                settlement_owner_chirho: None,
                idempotency_window_chirho: None,
            },
        );
        // A VALID, REGISTERED revision whose stable identity is points — the RK.1 wrong-kind bait.
        policies_chirho.insert(
            AssetKindRefChirho(DigestChirho(WRONGKIND_POLICY_REF_CHIRHO.into())),
            KindPolicyViewChirho {
                kind_id_chirho: POINTS_KIND_CHIRHO.into(),
                mint_authority_chirho: MintAuthorityPolicyChirho::PlatformPolicyChirho {
                    max_supply_chirho: None,
                },
                rounding_chirho: RoundingChirho::DownChirho,
                settlement_owner_chirho: None,
                idempotency_window_chirho: None,
            },
        );
        policies_chirho.insert(
            AssetKindRefChirho(DigestChirho(CLOSED_POLICY_REF_CHIRHO.into())),
            KindPolicyViewChirho {
                kind_id_chirho: CLOSED_KIND_CHIRHO.into(),
                mint_authority_chirho: MintAuthorityPolicyChirho::ClosedChirho,
                rounding_chirho: RoundingChirho::ExactChirho,
                settlement_owner_chirho: None,
                idempotency_window_chirho: None,
            },
        );
        let mut head_states_chirho = BTreeMap::new();
        head_states_chirho.insert(
            account_chirho("alice-chirho", MONEY_KIND_CHIRHO),
            post_chirho(100, 0, 0),
        );
        FixtureChirho {
            membership_chirho: StubMembershipChirho {
                members_chirho: [
                    "alice-chirho",
                    "bob-chirho",
                    "issuer-chirho",
                    "carol-chirho",
                ]
                .into_iter()
                .map(str::to_owned)
                .collect(),
                revoked_chirho: ["revoked-rev-chirho"]
                    .into_iter()
                    .map(str::to_owned)
                    .collect(),
            },
            registry_chirho: StubRegistryChirho {
                policies_chirho,
                superseded_chirho: BTreeSet::new(),
            },
            authority_chirho: StubAuthorityChirho,
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
            finality_stubs_chirho: None,
            cluster_chirho: ClusterIdChirho("cluster-fixture-chirho".into()),
        }
    }

    pub(crate) fn context_chirho(&self) -> AdmissionContextChirho<'_> {
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
            finality_chirho: self.finality_stubs_chirho.as_ref().map(|stubs_chirho| {
                FinalityAdmissionViewsChirho {
                    proofs_chirho: &stubs_chirho.proofs_chirho,
                    source_roots_chirho: &stubs_chirho.roots_chirho,
                    settlement_authorizations_chirho: &stubs_chirho.authorizations_chirho,
                }
            }),
            expected_anchor_chirho: None,
        }
    }
}

pub(crate) fn leg_chirho(
    owner_chirho: &str,
    kind_chirho: &str,
    policy_ref_chirho: &str,
    delta_chirho: LegDeltaChirho,
    amount_chirho: u64,
    post_state_chirho: LegPostStateChirho,
) -> LedgerLegChirho {
    LedgerLegChirho {
        account_chirho: account_chirho(owner_chirho, kind_chirho),
        kind_policy_ref_chirho: AssetKindRefChirho(DigestChirho(policy_ref_chirho.into())),
        delta_chirho,
        amount_chirho,
        post_chirho: post_state_chirho,
        counterpart_chirho: None,
    }
}

pub(crate) fn record_chirho(
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

/// alice(money, head 100/0/0) pays bob(money, lazy zero baseline) 40 — the canonical admit.
fn good_transfer_chirho() -> LedgerRecordChirho {
    record_chirho(
        LedgerOpChirho::TransferChirho,
        vec![
            leg_chirho(
                "alice-chirho",
                MONEY_KIND_CHIRHO,
                MONEY_POLICY_REF_CHIRHO,
                LegDeltaChirho::DebitChirho,
                40,
                post_chirho(100, 40, 0),
            ),
            leg_chirho(
                "bob-chirho",
                MONEY_KIND_CHIRHO,
                MONEY_POLICY_REF_CHIRHO,
                LegDeltaChirho::CreditChirho,
                40,
                post_chirho(40, 0, 0),
            ),
        ],
    )
}

fn good_mint_chirho(amount_chirho: u64) -> LedgerRecordChirho {
    record_chirho(
        LedgerOpChirho::MintChirho {
            authority_evidence_chirho: DigestChirho(GOOD_MINT_EVIDENCE_CHIRHO.into()),
        },
        vec![leg_chirho(
            "issuer-chirho",
            MONEY_KIND_CHIRHO,
            MONEY_POLICY_REF_CHIRHO,
            LegDeltaChirho::CreditChirho,
            amount_chirho,
            post_chirho(amount_chirho, 0, 0),
        )],
    )
}

fn money_asset_op_chirho(amount_chirho: u64, rounding_chirho: RoundingChirho) -> AssetOpChirho {
    AssetOpChirho {
        amount_chirho,
        kind_id_chirho: MONEY_KIND_CHIRHO.into(),
        kind_policy_ref_chirho: AssetKindRefChirho(DigestChirho(MONEY_POLICY_REF_CHIRHO.into())),
        rounding_chirho,
    }
}

fn split_transfer_chirho(
    whole_chirho: u64,
    derived_part_chirho: u64,
    counterpart_part_chirho: u64,
) -> LedgerRecordChirho {
    record_chirho(
        LedgerOpChirho::TransferChirho,
        vec![
            leg_chirho(
                "alice-chirho",
                MONEY_KIND_CHIRHO,
                MONEY_POLICY_REF_CHIRHO,
                LegDeltaChirho::DebitChirho,
                whole_chirho,
                post_chirho(100, whole_chirho, 0),
            ),
            leg_chirho(
                "bob-chirho",
                MONEY_KIND_CHIRHO,
                MONEY_POLICY_REF_CHIRHO,
                LegDeltaChirho::CreditChirho,
                derived_part_chirho,
                post_chirho(derived_part_chirho, 0, 0),
            ),
            leg_chirho(
                "carol-chirho",
                MONEY_KIND_CHIRHO,
                MONEY_POLICY_REF_CHIRHO,
                LegDeltaChirho::CreditChirho,
                counterpart_part_chirho,
                post_chirho(counterpart_part_chirho, 0, 0),
            ),
        ],
    )
}

#[test]
fn asset_op_rounding_is_resolved_from_immutable_kind_policy_chirho() {
    let candidate_chirho = split_transfer_chirho(40, 15, 25);
    let asset_op_chirho = money_asset_op_chirho(15, RoundingChirho::UpChirho);
    let default_fixture_chirho = FixtureChirho::new_chirho();
    assert!(matches!(
        admit_derived_asset_op_chirho(
            &default_fixture_chirho.context_chirho(),
            &asset_op_chirho,
            candidate_chirho.clone(),
        ),
        Err(AdmissionRejectChirho::AssetOpRoundingChirho { .. })
    ));

    // Change only the immutable registry view. The same caller value and record now admit, proving
    // the door reads the resolved policy rather than comparing against a caller-owned constant.
    let mut up_fixture_chirho = FixtureChirho::new_chirho();
    up_fixture_chirho
        .registry_chirho
        .policies_chirho
        .get_mut(&AssetKindRefChirho(DigestChirho(
            MONEY_POLICY_REF_CHIRHO.into(),
        )))
        .unwrap()
        .rounding_chirho = RoundingChirho::UpChirho;
    admit_derived_asset_op_chirho(
        &up_fixture_chirho.context_chirho(),
        &asset_op_chirho,
        candidate_chirho,
    )
    .unwrap();

    assert!(matches!(
        admit_derived_asset_op_chirho(
            &up_fixture_chirho.context_chirho(),
            &asset_op_chirho,
            good_mint_chirho(15),
        ),
        Err(AdmissionRejectChirho::AssetOpRecordMismatchChirho { .. })
    ));
}

#[test]
fn every_rounding_mode_still_requires_exact_same_record_conservation_chirho() {
    for rounding_chirho in [
        RoundingChirho::ExactChirho,
        RoundingChirho::DownChirho,
        RoundingChirho::UpChirho,
        RoundingChirho::NearestTiesToEvenChirho,
    ] {
        let mut fixture_chirho = FixtureChirho::new_chirho();
        fixture_chirho
            .registry_chirho
            .policies_chirho
            .get_mut(&AssetKindRefChirho(DigestChirho(
                MONEY_POLICY_REF_CHIRHO.into(),
            )))
            .unwrap()
            .rounding_chirho = rounding_chirho;
        let asset_op_chirho = money_asset_op_chirho(15, rounding_chirho);
        assert!(matches!(
            admit_derived_asset_op_chirho(
                &fixture_chirho.context_chirho(),
                &asset_op_chirho,
                split_transfer_chirho(40, 15, 24),
            ),
            Err(AdmissionRejectChirho::KindConservationChirho { .. })
        ));
    }

    let fixture_chirho = FixtureChirho::new_chirho();
    admit_derived_asset_op_chirho(
        &fixture_chirho.context_chirho(),
        &money_asset_op_chirho(15, RoundingChirho::NearestTiesToEvenChirho),
        split_transfer_chirho(40, 15, 25),
    )
    .unwrap();
}

#[test]
fn zero_asset_op_defers_to_each_ledger_operation_law_chirho() {
    let fixture_chirho = FixtureChirho::new_chirho();
    let context_chirho = fixture_chirho.context_chirho();
    let asset_op_chirho = money_asset_op_chirho(0, RoundingChirho::ExactChirho);
    let zero_transfer_chirho = record_chirho(
        LedgerOpChirho::TransferChirho,
        vec![
            leg_chirho(
                "alice-chirho",
                MONEY_KIND_CHIRHO,
                MONEY_POLICY_REF_CHIRHO,
                LegDeltaChirho::DebitChirho,
                0,
                post_chirho(100, 0, 0),
            ),
            leg_chirho(
                "bob-chirho",
                MONEY_KIND_CHIRHO,
                MONEY_POLICY_REF_CHIRHO,
                LegDeltaChirho::CreditChirho,
                0,
                post_chirho(0, 0, 0),
            ),
        ],
    );
    admit_plain_asset_op_chirho(&context_chirho, &asset_op_chirho, zero_transfer_chirho).unwrap();

    assert!(matches!(
        admit_plain_asset_op_chirho(&context_chirho, &asset_op_chirho, good_mint_chirho(0),),
        Err(AdmissionRejectChirho::ZeroAmountMintChirho)
    ));
    let zero_burn_chirho = record_chirho(
        LedgerOpChirho::BurnChirho {
            authority_evidence_chirho: DigestChirho(GOOD_BURN_EVIDENCE_CHIRHO.into()),
        },
        vec![leg_chirho(
            "alice-chirho",
            MONEY_KIND_CHIRHO,
            MONEY_POLICY_REF_CHIRHO,
            LegDeltaChirho::DebitChirho,
            0,
            post_chirho(100, 0, 0),
        )],
    );
    assert!(matches!(
        admit_plain_asset_op_chirho(&context_chirho, &asset_op_chirho, zero_burn_chirho),
        Err(AdmissionRejectChirho::ZeroAmountBurnChirho)
    ));
}

#[test]
fn positive_transfer_mint_burn_timer_admit_chirho() {
    let fixture_chirho = FixtureChirho::new_chirho();
    let context_chirho = fixture_chirho.context_chirho();
    // Transfer.
    let token_chirho = admit_chirho(&context_chirho, good_transfer_chirho()).unwrap();
    assert_eq!(token_chirho.record_chirho(), &good_transfer_chirho());
    // Mint (authorized, under cap).
    admit_chirho(&context_chirho, good_mint_chirho(100)).unwrap();
    // Burn (authorized, funded).
    let burn_chirho = record_chirho(
        LedgerOpChirho::BurnChirho {
            authority_evidence_chirho: DigestChirho(GOOD_BURN_EVIDENCE_CHIRHO.into()),
        },
        vec![leg_chirho(
            "alice-chirho",
            MONEY_KIND_CHIRHO,
            MONEY_POLICY_REF_CHIRHO,
            LegDeltaChirho::DebitChirho,
            30,
            post_chirho(100, 30, 0),
        )],
    );
    admit_chirho(&context_chirho, burn_chirho).unwrap();
    // Timer (zero money legs).
    let timer_chirho = record_chirho(
        LedgerOpChirho::TimerChirho {
            fires_at_hlc_chirho: HlcChirho {
                physical_ms_chirho: 5_000,
                logical_chirho: 0,
            },
            purpose_chirho: "sweep-chirho".into(),
        },
        vec![],
    );
    admit_chirho(&context_chirho, timer_chirho).unwrap();
}

#[test]
fn admission_token_derives_max_retention_from_deduped_touched_policies_chirho() {
    let mut fixture_chirho = FixtureChirho::new_chirho();
    fixture_chirho
        .registry_chirho
        .policies_chirho
        .get_mut(&AssetKindRefChirho(DigestChirho(
            MONEY_POLICY_REF_CHIRHO.to_owned(),
        )))
        .unwrap()
        .idempotency_window_chirho = Some(IdempotencyWindowPolicyViewChirho {
        idempotency_horizon_ms_chirho: 100,
        retry_finality_horizon_ms_chirho: 80,
    });
    fixture_chirho
        .registry_chirho
        .policies_chirho
        .get_mut(&AssetKindRefChirho(DigestChirho(
            POINTS_POLICY_REF_CHIRHO.to_owned(),
        )))
        .unwrap()
        .idempotency_window_chirho = Some(IdempotencyWindowPolicyViewChirho {
        idempotency_horizon_ms_chirho: 400,
        retry_finality_horizon_ms_chirho: 300,
    });
    fixture_chirho.head_states_chirho.insert(
        account_chirho("carol-chirho", POINTS_KIND_CHIRHO),
        post_chirho(100, 0, 0),
    );
    let candidate_chirho = record_chirho(
        LedgerOpChirho::TransferChirho,
        vec![
            leg_chirho(
                "alice-chirho",
                MONEY_KIND_CHIRHO,
                MONEY_POLICY_REF_CHIRHO,
                LegDeltaChirho::DebitChirho,
                10,
                post_chirho(100, 10, 0),
            ),
            leg_chirho(
                "bob-chirho",
                MONEY_KIND_CHIRHO,
                MONEY_POLICY_REF_CHIRHO,
                LegDeltaChirho::CreditChirho,
                10,
                post_chirho(10, 0, 0),
            ),
            leg_chirho(
                "carol-chirho",
                POINTS_KIND_CHIRHO,
                POINTS_POLICY_REF_CHIRHO,
                LegDeltaChirho::DebitChirho,
                20,
                post_chirho(100, 20, 0),
            ),
            leg_chirho(
                "bob-chirho",
                POINTS_KIND_CHIRHO,
                POINTS_POLICY_REF_CHIRHO,
                LegDeltaChirho::CreditChirho,
                20,
                post_chirho(20, 0, 0),
            ),
        ],
    );
    let token_chirho = admit_chirho(&fixture_chirho.context_chirho(), candidate_chirho.clone())
        .expect("both independently conserved kinds admit");
    assert_eq!(
        token_chirho.retention_chirho(),
        &IdempotencyRetentionChirho::BoundedChirho {
            policy_refs_chirho: vec![
                AssetKindRefChirho(DigestChirho(MONEY_POLICY_REF_CHIRHO.to_owned())),
                AssetKindRefChirho(DigestChirho(POINTS_POLICY_REF_CHIRHO.to_owned())),
            ],
            idempotency_horizon_ms_chirho: 400,
            retry_finality_horizon_ms_chirho: 300,
        }
    );

    fixture_chirho
        .registry_chirho
        .policies_chirho
        .get_mut(&AssetKindRefChirho(DigestChirho(
            MONEY_POLICY_REF_CHIRHO.to_owned(),
        )))
        .unwrap()
        .idempotency_window_chirho = None;
    let legacy_chirho = admit_chirho(&fixture_chirho.context_chirho(), candidate_chirho)
        .expect("missing window conservatively keeps the record unpruned");
    assert!(matches!(
        legacy_chirho.retention_chirho(),
        IdempotencyRetentionChirho::LegacyUnprunedChirho {
            policy_refs_chirho
        } if policy_refs_chirho.len() == 2
    ));
}

#[test]
fn record_internal_same_account_legs_chain_in_order_chirho() {
    // Fold order is leg order: a second leg on the SAME account folds from the first leg's result,
    // and each carried post must equal its own chained fold (§11.2 serial-within-batch law).
    let fixture_chirho = FixtureChirho::new_chirho();
    let record_chirho = record_chirho(
        LedgerOpChirho::TransferChirho,
        vec![
            leg_chirho(
                "alice-chirho",
                MONEY_KIND_CHIRHO,
                MONEY_POLICY_REF_CHIRHO,
                LegDeltaChirho::DebitChirho,
                40,
                post_chirho(100, 40, 0),
            ),
            leg_chirho(
                "alice-chirho",
                MONEY_KIND_CHIRHO,
                MONEY_POLICY_REF_CHIRHO,
                LegDeltaChirho::CreditChirho,
                40,
                post_chirho(140, 40, 0),
            ),
        ],
    );
    admit_chirho(&fixture_chirho.context_chirho(), record_chirho).unwrap();
}

#[test]
fn wire_and_journal_fencing_reject_chirho() {
    let fixture_chirho = FixtureChirho::new_chirho();
    let context_chirho = fixture_chirho.context_chirho();
    // Wrong in-memory schema tag refuses at the wire step.
    let mut bad_schema_chirho = good_transfer_chirho();
    bad_schema_chirho.schema_chirho = "ledger-record-v9-chirho".into();
    assert!(matches!(
        admit_chirho(&context_chirho, bad_schema_chirho),
        Err(AdmissionRejectChirho::WireChirho { .. })
    ));
    // Stale seq (a record prepared against an older tail).
    let mut stale_seq_chirho = good_transfer_chirho();
    stale_seq_chirho.seq_chirho = 7;
    assert!(matches!(
        admit_chirho(&context_chirho, stale_seq_chirho),
        Err(AdmissionRejectChirho::SeqMismatchChirho {
            expected_chirho: 1,
            found_chirho: 7
        })
    ));
    // Wrong prev (chain fork attempt).
    let mut wrong_prev_chirho = good_transfer_chirho();
    wrong_prev_chirho.prev_chirho = DigestChirho("forged-tail-chirho".into());
    assert!(matches!(
        admit_chirho(&context_chirho, wrong_prev_chirho),
        Err(AdmissionRejectChirho::PrevMismatchChirho)
    ));
    // Wrong epoch (lease fence: a stale-lease writer self-identifies, §11.5).
    let mut wrong_epoch_chirho = good_transfer_chirho();
    wrong_epoch_chirho.epoch_chirho = 9;
    assert!(matches!(
        admit_chirho(&context_chirho, wrong_epoch_chirho),
        Err(AdmissionRejectChirho::EpochMismatchChirho {
            expected_chirho: 1,
            found_chirho: 9
        })
    ));
    // Non-monotone HLC (equal to tail refuses; strictly-greater is required).
    let mut stale_hlc_chirho = good_transfer_chirho();
    stale_hlc_chirho.hlc_chirho = HlcChirho {
        physical_ms_chirho: 900,
        logical_chirho: 0,
    };
    assert!(matches!(
        admit_chirho(&context_chirho, stale_hlc_chirho),
        Err(AdmissionRejectChirho::HlcNotMonotoneChirho)
    ));
    // Duplicate idempotency key inside the window.
    let mut window_fixture_chirho = FixtureChirho::new_chirho();
    window_fixture_chirho
        .recent_idempotency_keys_chirho
        .insert("idem-1-chirho".into());
    assert!(matches!(
        admit_chirho(
            &window_fixture_chirho.context_chirho(),
            good_transfer_chirho()
        ),
        Err(AdmissionRejectChirho::IdempotencyDuplicateChirho)
    ));
}

#[test]
fn grammar_rejects_unsupported_and_bad_shapes_chirho() {
    let fixture_chirho = FixtureChirho::new_chirho();
    let context_chirho = fixture_chirho.context_chirho();
    // ExplicitlyUnsupported ops — bare Credit/Debit (free mint / unbound destruction) and
    // Compensation, even in canonical shape (E.1/E.2). The escrow family LEFT this list at CF2.
    let unsupported_chirho: Vec<LedgerRecordChirho> = vec![
        record_chirho(
            LedgerOpChirho::CreditChirho,
            vec![leg_chirho(
                "bob-chirho",
                MONEY_KIND_CHIRHO,
                MONEY_POLICY_REF_CHIRHO,
                LegDeltaChirho::CreditChirho,
                5,
                post_chirho(5, 0, 0),
            )],
        ),
        record_chirho(
            LedgerOpChirho::DebitChirho,
            vec![leg_chirho(
                "alice-chirho",
                MONEY_KIND_CHIRHO,
                MONEY_POLICY_REF_CHIRHO,
                LegDeltaChirho::DebitChirho,
                5,
                post_chirho(100, 5, 0),
            )],
        ),
        record_chirho(
            LedgerOpChirho::CompensationChirho {
                of_chirho: DigestChirho("prior-chirho".into()),
            },
            vec![],
        ),
    ];
    for candidate_chirho in unsupported_chirho {
        assert!(matches!(
            admit_chirho(&context_chirho, candidate_chirho),
            Err(AdmissionRejectChirho::UnsupportedOperationChirho)
        ));
    }
    // CF2: the escrow family is now GRAMMAR, not Unsupported. A canonical fresh Hold ADMITS
    // (shape row + 9b fresh key + F4 floor 100 >= 10 + fold-true post)...
    admit_chirho(
        &context_chirho,
        record_chirho(
            LedgerOpChirho::EscrowHoldChirho {
                control_chirho: EscrowControlChirho {
                    saga_id_chirho: DigestChirho("saga-fixture-chirho".into()),
                    step_chirho: 1,
                },
            },
            vec![leg_chirho(
                "alice-chirho",
                MONEY_KIND_CHIRHO,
                MONEY_POLICY_REF_CHIRHO,
                LegDeltaChirho::HoldChirho,
                10,
                post_chirho(100, 0, 10),
            )],
        ),
    )
    .expect("canonical fresh escrow hold admits under the CF2 grammar");
    // ...a Finalize naming a hold this ledger never made refuses at the escrow law (proving it
    // got PAST grammar), not as Unsupported...
    assert!(matches!(
        admit_chirho(
            &context_chirho,
            record_chirho(
                LedgerOpChirho::EscrowFinalizeChirho {
                    control_chirho: EscrowControlChirho {
                        saga_id_chirho: DigestChirho("saga-fixture-chirho".into()),
                        step_chirho: 1,
                    },
                },
                vec![
                    leg_chirho(
                        "alice-chirho",
                        MONEY_KIND_CHIRHO,
                        MONEY_POLICY_REF_CHIRHO,
                        LegDeltaChirho::FinalizeChirho,
                        10,
                        post_chirho(100, 10, 0),
                    ),
                    leg_chirho(
                        "carol-chirho",
                        MONEY_KIND_CHIRHO,
                        MONEY_POLICY_REF_CHIRHO,
                        LegDeltaChirho::CreditChirho,
                        10,
                        post_chirho(10, 0, 0),
                    ),
                ],
            ),
        ),
        Err(AdmissionRejectChirho::UnknownEscrowHoldChirho)
    ));
    // ...and a legless Release is a SHAPE refusal (exactly one Release leg required).
    assert!(matches!(
        admit_chirho(
            &context_chirho,
            record_chirho(
                LedgerOpChirho::EscrowReleaseChirho {
                    control_chirho: EscrowControlChirho {
                        saga_id_chirho: DigestChirho("saga-fixture-chirho".into()),
                        step_chirho: 1,
                    },
                },
                vec![],
            ),
        ),
        Err(AdmissionRejectChirho::BadShapeChirho { .. })
    ));
    // The Transfer discriminator: a counterpart-bearing Transfer is the x-cluster settlement FORM —
    // UnsupportedOperation in CF1 (never BadShape, never silently internal).
    let mut settlement_chirho = good_transfer_chirho();
    settlement_chirho.legs_chirho[1].counterpart_chirho = Some(
        cairn_ledger_model_chirho::counterpart_chirho::CounterpartClaimChirho {
            transfer_id_chirho: TransferIdChirho("t-1-chirho".into()),
            burn_chirho: cairn_ledger_model_chirho::counterpart_chirho::FinalBurnRefChirho {
                source_money_group_chirho: MoneyGroupIdChirho("mg-chirho".into()),
                source_cluster_chirho: ClusterIdChirho("cl-chirho".into()),
                source_epoch_chirho: 1,
                source_seq_chirho: 1,
                source_record_digest_chirho: DigestChirho("burn-chirho".into()),
                finality_proof_ref_chirho: DigestChirho("proof-chirho".into()),
            },
            amount_chirho: 40,
            kind_policy_ref_chirho: AssetKindRefChirho(DigestChirho(
                MONEY_POLICY_REF_CHIRHO.into(),
            )),
            src_chirho: account_chirho("carol-chirho", MONEY_KIND_CHIRHO),
            dst_money_group_chirho: MoneyGroupIdChirho("mg-chirho".into()),
            dst_cluster_chirho: ClusterIdChirho("cl-chirho".into()),
            dst_chirho: account_chirho("bob-chirho", MONEY_KIND_CHIRHO),
            channel_chirho: SettlementChannelIdChirho("chan-chirho".into()),
            nullifier_chirho:
                cairn_ledger_model_chirho::counterpart_chirho::CounterpartNullifierChirho(
                    DigestChirho("null-chirho".into()),
                ),
        },
    );
    assert!(matches!(
        admit_chirho(&context_chirho, settlement_chirho),
        Err(AdmissionRejectChirho::UnsupportedOperationChirho)
    ));
    // Shape REDs.
    let one_leg_transfer_chirho = record_chirho(
        LedgerOpChirho::TransferChirho,
        vec![leg_chirho(
            "alice-chirho",
            MONEY_KIND_CHIRHO,
            MONEY_POLICY_REF_CHIRHO,
            LegDeltaChirho::DebitChirho,
            5,
            post_chirho(100, 5, 0),
        )],
    );
    assert!(matches!(
        admit_chirho(&context_chirho, one_leg_transfer_chirho),
        Err(AdmissionRejectChirho::BadShapeChirho { .. })
    ));
    let mut hold_transfer_chirho = good_transfer_chirho();
    hold_transfer_chirho.legs_chirho[1].delta_chirho = LegDeltaChirho::HoldChirho;
    assert!(matches!(
        admit_chirho(&context_chirho, hold_transfer_chirho),
        Err(AdmissionRejectChirho::BadShapeChirho { .. })
    ));
    let mint_debit_chirho = record_chirho(
        LedgerOpChirho::MintChirho {
            authority_evidence_chirho: DigestChirho(GOOD_MINT_EVIDENCE_CHIRHO.into()),
        },
        vec![leg_chirho(
            "issuer-chirho",
            MONEY_KIND_CHIRHO,
            MONEY_POLICY_REF_CHIRHO,
            LegDeltaChirho::DebitChirho,
            5,
            post_chirho(0, 5, 0),
        )],
    );
    assert!(matches!(
        admit_chirho(&context_chirho, mint_debit_chirho),
        Err(AdmissionRejectChirho::BadShapeChirho { .. })
    ));
    let burn_credit_chirho = record_chirho(
        LedgerOpChirho::BurnChirho {
            authority_evidence_chirho: DigestChirho(GOOD_BURN_EVIDENCE_CHIRHO.into()),
        },
        vec![leg_chirho(
            "alice-chirho",
            MONEY_KIND_CHIRHO,
            MONEY_POLICY_REF_CHIRHO,
            LegDeltaChirho::CreditChirho,
            5,
            post_chirho(105, 0, 0),
        )],
    );
    assert!(matches!(
        admit_chirho(&context_chirho, burn_credit_chirho),
        Err(AdmissionRejectChirho::BadShapeChirho { .. })
    ));
    let timer_with_leg_chirho = record_chirho(
        LedgerOpChirho::TimerChirho {
            fires_at_hlc_chirho: HlcChirho {
                physical_ms_chirho: 5_000,
                logical_chirho: 0,
            },
            purpose_chirho: "sweep-chirho".into(),
        },
        vec![leg_chirho(
            "alice-chirho",
            MONEY_KIND_CHIRHO,
            MONEY_POLICY_REF_CHIRHO,
            LegDeltaChirho::CreditChirho,
            1,
            post_chirho(101, 0, 0),
        )],
    );
    assert!(matches!(
        admit_chirho(&context_chirho, timer_with_leg_chirho),
        Err(AdmissionRejectChirho::BadShapeChirho { .. })
    ));
}

#[test]
fn membership_fires_on_its_own_dimension_chirho() {
    let fixture_chirho = FixtureChirho::new_chirho();
    let context_chirho = fixture_chirho.context_chirho();
    // R1.1: non-member PAYEE — the credit leg is checked too.
    let mut credit_outsider_chirho = good_transfer_chirho();
    credit_outsider_chirho.legs_chirho[1].account_chirho =
        account_chirho("mallory-chirho", MONEY_KIND_CHIRHO);
    assert!(matches!(
        admit_chirho(&context_chirho, credit_outsider_chirho),
        Err(AdmissionRejectChirho::NonMemberChirho { owner_chirho }) if owner_chirho == "mallory-chirho"
    ));
    // R1.2: non-member PAYER, FUNDED so the fence would pass — the reject must be membership,
    // proving the dimension (not an accidental overdraft reject).
    let mut funded_fixture_chirho = FixtureChirho::new_chirho();
    funded_fixture_chirho.head_states_chirho.insert(
        account_chirho("mallory-chirho", MONEY_KIND_CHIRHO),
        post_chirho(100, 0, 0),
    );
    let mut debit_outsider_chirho = good_transfer_chirho();
    debit_outsider_chirho.legs_chirho[0].account_chirho =
        account_chirho("mallory-chirho", MONEY_KIND_CHIRHO);
    assert!(matches!(
        admit_chirho(&funded_fixture_chirho.context_chirho(), debit_outsider_chirho),
        Err(AdmissionRejectChirho::NonMemberChirho { owner_chirho }) if owner_chirho == "mallory-chirho"
    ));
    // R1.3: mint into a non-member — VALID authority, still refused on membership.
    let mut mint_outsider_chirho = good_mint_chirho(50);
    mint_outsider_chirho.legs_chirho[0].account_chirho =
        account_chirho("mallory-chirho", MONEY_KIND_CHIRHO);
    assert!(matches!(
        admit_chirho(&context_chirho, mint_outsider_chirho),
        Err(AdmissionRejectChirho::NonMemberChirho { .. })
    ));
    // R1.4: revoked member.
    let mut revoked_fixture_chirho = FixtureChirho::new_chirho();
    revoked_fixture_chirho
        .membership_chirho
        .members_chirho
        .insert("revoked-rev-chirho".into());
    revoked_fixture_chirho.head_states_chirho.insert(
        account_chirho("revoked-rev-chirho", MONEY_KIND_CHIRHO),
        post_chirho(100, 0, 0),
    );
    let mut revoked_chirho = good_transfer_chirho();
    revoked_chirho.legs_chirho[0].account_chirho =
        account_chirho("revoked-rev-chirho", MONEY_KIND_CHIRHO);
    assert!(matches!(
        admit_chirho(&revoked_fixture_chirho.context_chirho(), revoked_chirho),
        Err(AdmissionRejectChirho::RevokedMemberChirho { owner_chirho }) if owner_chirho == "revoked-rev-chirho"
    ));
}

#[test]
fn kind_identity_binding_fires_chirho() {
    let fixture_chirho = FixtureChirho::new_chirho();
    let context_chirho = fixture_chirho.context_chirho();
    // RK.2: unregistered policy ref — fail-closed, never "its own bucket".
    let mut unregistered_chirho = good_transfer_chirho();
    unregistered_chirho.legs_chirho[0].kind_policy_ref_chirho =
        AssetKindRefChirho(DigestChirho("policy-nowhere-chirho".into()));
    assert!(matches!(
        admit_chirho(&context_chirho, unregistered_chirho),
        Err(AdmissionRejectChirho::UnknownKindPolicyChirho)
    ));
    // RK.1: a VALID REGISTERED revision resolving to the WRONG stable kind for this account.
    let mut mismatched_chirho = good_transfer_chirho();
    mismatched_chirho.legs_chirho[1].kind_policy_ref_chirho =
        AssetKindRefChirho(DigestChirho(WRONGKIND_POLICY_REF_CHIRHO.into()));
    assert!(matches!(
        admit_chirho(&context_chirho, mismatched_chirho),
        Err(AdmissionRejectChirho::KindIdentityMismatchChirho)
    ));
}

#[test]
fn per_stable_kind_conservation_fires_chirho() {
    let fixture_chirho = FixtureChirho::new_chirho();
    let context_chirho = fixture_chirho.context_chirho();
    // Cross-kind "balanced" transfer: money Debit 40 funding points Credit 40 — Σ per stable kind
    // is −40/+40, both non-zero; a Debit of X can never fund a Credit of Y (R5a).
    let mut points_fixture_chirho = FixtureChirho::new_chirho();
    points_fixture_chirho.head_states_chirho.insert(
        account_chirho("alice-chirho", MONEY_KIND_CHIRHO),
        post_chirho(100, 0, 0),
    );
    let cross_kind_chirho = record_chirho(
        LedgerOpChirho::TransferChirho,
        vec![
            leg_chirho(
                "alice-chirho",
                MONEY_KIND_CHIRHO,
                MONEY_POLICY_REF_CHIRHO,
                LegDeltaChirho::DebitChirho,
                40,
                post_chirho(100, 40, 0),
            ),
            leg_chirho(
                "bob-chirho",
                POINTS_KIND_CHIRHO,
                POINTS_POLICY_REF_CHIRHO,
                LegDeltaChirho::CreditChirho,
                40,
                post_chirho(40, 0, 0),
            ),
        ],
    );
    assert!(matches!(
        admit_chirho(&points_fixture_chirho.context_chirho(), cross_kind_chirho),
        Err(AdmissionRejectChirho::KindConservationChirho { kind_id_chirho }) if kind_id_chirho.0 == MONEY_KIND_CHIRHO
    ));
    // Plain unbalanced same-kind transfer.
    let mut unbalanced_chirho = good_transfer_chirho();
    unbalanced_chirho.legs_chirho[1].amount_chirho = 39;
    unbalanced_chirho.legs_chirho[1].post_chirho = post_chirho(39, 0, 0);
    assert!(matches!(
        admit_chirho(&context_chirho, unbalanced_chirho),
        Err(AdmissionRejectChirho::KindConservationChirho { .. })
    ));
}

#[test]
fn mint_burn_authority_and_supply_fire_chirho() {
    let fixture_chirho = FixtureChirho::new_chirho();
    let context_chirho = fixture_chirho.context_chirho();
    // R2.1 wiring: unresolvable evidence — presence of a digest is NOT sufficient.
    let mut forged_mint_chirho = good_mint_chirho(100);
    if let LedgerOpChirho::MintChirho {
        authority_evidence_chirho,
    } = &mut forged_mint_chirho.op_chirho
    {
        *authority_evidence_chirho = DigestChirho("evidence-nowhere-chirho".into());
    }
    assert!(matches!(
        admit_chirho(&context_chirho, forged_mint_chirho),
        Err(AdmissionRejectChirho::MintAuthorityUnverifiedChirho)
    ));
    // R2.2 wiring: a grant that does not COVER this kind.
    let mut wrong_kind_mint_chirho = good_mint_chirho(100);
    if let LedgerOpChirho::MintChirho {
        authority_evidence_chirho,
    } = &mut wrong_kind_mint_chirho.op_chirho
    {
        *authority_evidence_chirho = DigestChirho(WRONGKIND_EVIDENCE_CHIRHO.into());
    }
    assert!(matches!(
        admit_chirho(&context_chirho, wrong_kind_mint_chirho),
        Err(AdmissionRejectChirho::MintAuthorityWrongKindChirho)
    ));
    // Authority gates FIRST (claude2 #4526): an UNAUTHORIZED over-cap mint reports the AUTHORITY
    // dimension, never the cap — an unauthorized caller cannot probe supply/cap state.
    let mut probe_fixture_chirho = FixtureChirho::new_chirho();
    probe_fixture_chirho
        .supply_by_kind_chirho
        .insert(MONEY_KIND_CHIRHO.into(), 950);
    let mut unauthorized_overcap_chirho = good_mint_chirho(100);
    if let LedgerOpChirho::MintChirho {
        authority_evidence_chirho,
    } = &mut unauthorized_overcap_chirho.op_chirho
    {
        *authority_evidence_chirho = DigestChirho("evidence-nowhere-chirho".into());
    }
    assert!(matches!(
        admit_chirho(
            &probe_fixture_chirho.context_chirho(),
            unauthorized_overcap_chirho
        ),
        Err(AdmissionRejectChirho::MintAuthorityUnverifiedChirho)
    ));
    // R2.3: cumulative supply cap — each mint individually authorized, the SUM breaches.
    let mut near_cap_fixture_chirho = FixtureChirho::new_chirho();
    near_cap_fixture_chirho
        .supply_by_kind_chirho
        .insert(MONEY_KIND_CHIRHO.into(), 950);
    assert!(matches!(
        admit_chirho(
            &near_cap_fixture_chirho.context_chirho(),
            good_mint_chirho(100)
        ),
        Err(AdmissionRejectChirho::SupplyCapExceededChirho)
    ));
    // Exactly AT the cap still admits (the bound is inclusive).
    let mut at_cap_fixture_chirho = FixtureChirho::new_chirho();
    at_cap_fixture_chirho
        .supply_by_kind_chirho
        .insert(MONEY_KIND_CHIRHO.into(), 900);
    admit_chirho(
        &at_cap_fixture_chirho.context_chirho(),
        good_mint_chirho(100),
    )
    .unwrap();
    // R2.5 pinned STRICT: a zero-amount mint is refused (never a silent supply-aggregate hole).
    assert!(matches!(
        admit_chirho(&context_chirho, good_mint_chirho(0)),
        Err(AdmissionRejectChirho::ZeroAmountMintChirho)
    ));
    // A Closed kind mints for nobody.
    let closed_mint_chirho = record_chirho(
        LedgerOpChirho::MintChirho {
            authority_evidence_chirho: DigestChirho(GOOD_MINT_EVIDENCE_CHIRHO.into()),
        },
        vec![leg_chirho(
            "issuer-chirho",
            CLOSED_KIND_CHIRHO,
            CLOSED_POLICY_REF_CHIRHO,
            LegDeltaChirho::CreditChirho,
            5,
            post_chirho(5, 0, 0),
        )],
    );
    assert!(matches!(
        admit_chirho(&context_chirho, closed_mint_chirho),
        Err(AdmissionRejectChirho::MintClosedKindChirho)
    ));
    // R2.4 wiring: a "burn" with unresolvable evidence is theft-by-destruction — the FOLD is valid
    // (funded member, spendable stays ≥ 0), so the reject MUST be the authority dimension.
    let forged_burn_chirho = record_chirho(
        LedgerOpChirho::BurnChirho {
            authority_evidence_chirho: DigestChirho("evidence-nowhere-chirho".into()),
        },
        vec![leg_chirho(
            "alice-chirho",
            MONEY_KIND_CHIRHO,
            MONEY_POLICY_REF_CHIRHO,
            LegDeltaChirho::DebitChirho,
            30,
            post_chirho(100, 30, 0),
        )],
    );
    assert!(matches!(
        admit_chirho(&context_chirho, forged_burn_chirho),
        Err(AdmissionRejectChirho::BurnAuthorityUnverifiedChirho)
    ));
    // Zero-amount burn: refused symmetrically.
    let zero_burn_chirho = record_chirho(
        LedgerOpChirho::BurnChirho {
            authority_evidence_chirho: DigestChirho(GOOD_BURN_EVIDENCE_CHIRHO.into()),
        },
        vec![leg_chirho(
            "alice-chirho",
            MONEY_KIND_CHIRHO,
            MONEY_POLICY_REF_CHIRHO,
            LegDeltaChirho::DebitChirho,
            0,
            post_chirho(100, 0, 0),
        )],
    );
    assert!(matches!(
        admit_chirho(&context_chirho, zero_burn_chirho),
        Err(AdmissionRejectChirho::ZeroAmountBurnChirho)
    ));
}

#[test]
fn append_time_fence_recomputes_every_post_chirho() {
    let fixture_chirho = FixtureChirho::new_chirho();
    let context_chirho = fixture_chirho.context_chirho();
    // F1 stale-credit trap: bob's TRUE head moved (credits 10) after this record precomputed its
    // post against the old zero baseline — accepting the stale post would silently LOSE the 10.
    let mut moved_fixture_chirho = FixtureChirho::new_chirho();
    moved_fixture_chirho.head_states_chirho.insert(
        account_chirho("bob-chirho", MONEY_KIND_CHIRHO),
        post_chirho(10, 0, 0),
    );
    assert!(matches!(
        admit_chirho(
            &moved_fixture_chirho.context_chirho(),
            good_transfer_chirho()
        ),
        Err(AdmissionRejectChirho::PostStateMismatchChirho {
            leg_index_chirho: 1
        })
    ));
    // F4: overdraft — spendable floor fires (with a post that matches its own bad fold).
    let overdraft_chirho = record_chirho(
        LedgerOpChirho::TransferChirho,
        vec![
            leg_chirho(
                "alice-chirho",
                MONEY_KIND_CHIRHO,
                MONEY_POLICY_REF_CHIRHO,
                LegDeltaChirho::DebitChirho,
                150,
                post_chirho(100, 150, 0),
            ),
            leg_chirho(
                "bob-chirho",
                MONEY_KIND_CHIRHO,
                MONEY_POLICY_REF_CHIRHO,
                LegDeltaChirho::CreditChirho,
                150,
                post_chirho(150, 0, 0),
            ),
        ],
    );
    assert!(matches!(
        admit_chirho(&context_chirho, overdraft_chirho),
        Err(AdmissionRejectChirho::SpendableFloorChirho {
            leg_index_chirho: 0
        })
    ));
    // Checked math: a credit that would overflow u64 REFUSES (money never wraps).
    let mut overflow_fixture_chirho = FixtureChirho::new_chirho();
    overflow_fixture_chirho.head_states_chirho.insert(
        account_chirho("bob-chirho", MONEY_KIND_CHIRHO),
        post_chirho(u64::MAX, 0, 0),
    );
    assert!(matches!(
        admit_chirho(
            &overflow_fixture_chirho.context_chirho(),
            good_transfer_chirho()
        ),
        Err(AdmissionRejectChirho::ArithmeticChirho)
    ));
}

/// K4 (claude2 #4866 c-i): a SUPERSEDED policy ref refuses new admissions with its OWN typed
/// reject — minting under a stale (e.g. previously-uncapped) revision is the policy-downgrade
/// attack, and its refusal must never be confusable with an unknown/typo'd ref.
#[test]
fn superseded_policy_ref_refuses_distinctly_chirho() {
    let mut fixture_chirho = FixtureChirho::new_chirho();
    let money_ref_chirho = AssetKindRefChirho(DigestChirho(MONEY_POLICY_REF_CHIRHO.into()));
    fixture_chirho
        .registry_chirho
        .superseded_chirho
        .insert(money_ref_chirho);
    assert!(matches!(
        admit_chirho(&fixture_chirho.context_chirho(), good_mint_chirho(50)),
        Err(AdmissionRejectChirho::SupersededKindPolicyChirho)
    ));
    // The DISTINCT half: an unknown ref still lands on Unknown, never Superseded.
    let mut unknown_fixture_chirho = FixtureChirho::new_chirho();
    unknown_fixture_chirho
        .registry_chirho
        .policies_chirho
        .remove(&AssetKindRefChirho(DigestChirho(
            MONEY_POLICY_REF_CHIRHO.into(),
        )));
    assert!(matches!(
        admit_chirho(
            &unknown_fixture_chirho.context_chirho(),
            good_mint_chirho(50)
        ),
        Err(AdmissionRejectChirho::UnknownKindPolicyChirho)
    ));
}
