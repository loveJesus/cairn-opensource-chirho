// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! CF2 escrow journal proofs (split from journal_tests per the file-cap signal): the live
//! hold/release/finalize lifecycle, replay equivalence, the decoy-hold double-settlement RED,
//! the colluding-signer forged-release load twin (P2), and the fast-open holds-index restore.

use crate::admission_chirho::{
    AdmissionRejectChirho, IdempotencyWindowPolicyViewChirho, KindPolicyViewChirho,
    KindRegistryViewChirho, KindResolutionChirho, MintAuthorityPolicyChirho,
    RecordedRetentionWindowChirho,
};
use crate::checkpoint_chirho::{
    canonical_head_checkpoint_bytes_chirho, parse_head_checkpoint_chirho,
};
use crate::journal_chirho::{
    AppendLegRequestChirho, AppendRequestChirho, JournalErrorChirho, JournalPortsChirho,
    LedgerJournalChirho,
};
use crate::journal_tests_chirho::{mint_request_chirho, transfer_request_chirho, HarnessChirho};
use crate::ports_chirho::{LedgerSignerPortChirho, LedgerStoragePortChirho, StoragePathChirho};
use cairn_effect_commit_chirho::intent_chirho::{
    canonical_effect_intent_line_chirho, effect_intent_key_chirho, effect_intent_ref_chirho,
    sign_effect_intent_chirho, EffectIntentChirho, EffectIntentSignerPortChirho,
    EFFECT_INTENT_KEY_PREFIX_CHIRHO, EFFECT_INTENT_SCHEMA_V1_CHIRHO,
};
use cairn_ledger_model_chirho::asset_op_chirho::{AssetOpChirho, RoundingChirho};
use cairn_ledger_model_chirho::ids_chirho::{AssetKindIdChirho, AssetKindRefChirho, DigestChirho};
use cairn_ledger_model_chirho::record_chirho::{
    AttributionChirho, EscrowControlChirho, LedgerLegChirho, LedgerOpChirho, LedgerRecordChirho,
    LegDeltaChirho, LegPostStateChirho,
};
use cairn_ledger_model_chirho::wire_chirho::{
    canonical_ledger_record_line_chirho, ledger_record_signed_content_line_chirho,
    parse_canonical_ledger_journal_line_chirho, stored_line_digest_chirho, LedgerJournalLineChirho,
};
use cairn_ledger_model_chirho::LogIdChirho;
use std::cell::Cell;

const MONEY_KIND_CHIRHO: &str = "money-chirho";
const MONEY_POLICY_REF_CHIRHO: &str = "policy-money-v1-chirho";
const MONEY_POLICY_REF_V2_CHIRHO: &str = "policy-money-v2-chirho";
const DIGEST_A_CHIRHO: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DIGEST_B_CHIRHO: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const DIGEST_C_CHIRHO: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const DIGEST_D_CHIRHO: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

struct FakeEffectIntentSignerChirho {
    root_chirho: &'static str,
}

impl EffectIntentSignerPortChirho for FakeEffectIntentSignerChirho {
    fn sign_chirho(&self, signed_content_line_chirho: &str) -> anyhow::Result<String> {
        let mut hasher_chirho = blake3::Hasher::new();
        hasher_chirho.update(self.root_chirho.as_bytes());
        hasher_chirho.update(signed_content_line_chirho.as_bytes());
        Ok(hasher_chirho.finalize().to_hex().to_string())
    }

    fn key_id_chirho(&self) -> String {
        format!("{}-key-chirho", self.root_chirho)
    }

    fn verify_chirho(&self, signed_content_line_chirho: &str, sig_chirho: &str) -> bool {
        self.sign_chirho(signed_content_line_chirho)
            .is_ok_and(|expected_chirho| expected_chirho == sig_chirho)
    }
}

struct UnboundedMoneyRegistryChirho;

impl KindRegistryViewChirho for UnboundedMoneyRegistryChirho {
    fn resolve_chirho(&self, policy_ref_chirho: &AssetKindRefChirho) -> KindResolutionChirho {
        (policy_ref_chirho.0 .0 == MONEY_POLICY_REF_CHIRHO)
            .then(|| KindPolicyViewChirho {
                kind_id_chirho: AssetKindIdChirho(MONEY_KIND_CHIRHO.to_owned()),
                mint_authority_chirho: MintAuthorityPolicyChirho::PlatformPolicyChirho {
                    max_supply_chirho: Some(1_000),
                },
                rounding_chirho: RoundingChirho::NearestTiesToEvenChirho,
                settlement_owner_chirho: None,
                idempotency_window_chirho: None,
            })
            .map_or(
                KindResolutionChirho::UnknownChirho,
                KindResolutionChirho::CurrentChirho,
            )
    }
}

struct ExtendingMoneyRegistryChirho {
    superseded_chirho: Cell<bool>,
}

impl ExtendingMoneyRegistryChirho {
    fn policy_chirho(idempotency_horizon_ms_chirho: u64) -> KindPolicyViewChirho {
        KindPolicyViewChirho {
            kind_id_chirho: AssetKindIdChirho(MONEY_KIND_CHIRHO.to_owned()),
            mint_authority_chirho: MintAuthorityPolicyChirho::PlatformPolicyChirho {
                max_supply_chirho: Some(1_000),
            },
            rounding_chirho: RoundingChirho::NearestTiesToEvenChirho,
            settlement_owner_chirho: None,
            idempotency_window_chirho: Some(IdempotencyWindowPolicyViewChirho {
                idempotency_horizon_ms_chirho,
                retry_finality_horizon_ms_chirho: idempotency_horizon_ms_chirho / 2,
            }),
        }
    }
}

impl KindRegistryViewChirho for ExtendingMoneyRegistryChirho {
    fn resolve_chirho(&self, policy_ref_chirho: &AssetKindRefChirho) -> KindResolutionChirho {
        match (
            policy_ref_chirho.0 .0.as_str(),
            self.superseded_chirho.get(),
        ) {
            (MONEY_POLICY_REF_CHIRHO, false) => {
                KindResolutionChirho::CurrentChirho(Self::policy_chirho(100))
            }
            (MONEY_POLICY_REF_CHIRHO, true) => KindResolutionChirho::SupersededChirho,
            (MONEY_POLICY_REF_V2_CHIRHO, true) => {
                KindResolutionChirho::CurrentChirho(Self::policy_chirho(200))
            }
            _ => KindResolutionChirho::UnknownChirho,
        }
    }

    fn resolve_recorded_ref_retention_window_chirho(
        &self,
        policy_ref_chirho: &AssetKindRefChirho,
    ) -> RecordedRetentionWindowChirho {
        let recognized_chirho = matches!(
            policy_ref_chirho.0 .0.as_str(),
            MONEY_POLICY_REF_CHIRHO | MONEY_POLICY_REF_V2_CHIRHO
        );
        if !recognized_chirho {
            return RecordedRetentionWindowChirho::RetainIndefinitelyChirho;
        }
        let horizon_chirho = if self.superseded_chirho.get() {
            200
        } else {
            100
        };
        RecordedRetentionWindowChirho::BoundedChirho(IdempotencyWindowPolicyViewChirho {
            idempotency_horizon_ms_chirho: horizon_chirho,
            retry_finality_horizon_ms_chirho: horizon_chirho / 2,
        })
    }
}

fn escrow_control_chirho(saga_tag_chirho: &str, step_chirho: u32) -> EscrowControlChirho {
    EscrowControlChirho {
        saga_id_chirho: DigestChirho(format!("saga-{saga_tag_chirho}-chirho")),
        step_chirho,
    }
}

fn escrow_leg_request_chirho(
    owner_chirho: &str,
    delta_chirho: LegDeltaChirho,
    amount_chirho: u64,
) -> AppendLegRequestChirho {
    AppendLegRequestChirho {
        account_chirho: LogIdChirho::new_chirho(owner_chirho, MONEY_KIND_CHIRHO),
        kind_policy_ref_chirho: AssetKindRefChirho(DigestChirho(MONEY_POLICY_REF_CHIRHO.into())),
        delta_chirho,
        amount_chirho,
        counterpart_chirho: None,
    }
}

fn escrow_hold_request_chirho(
    owner_chirho: &str,
    amount_chirho: u64,
    saga_tag_chirho: &str,
    step_chirho: u32,
    idem_chirho: &str,
) -> AppendRequestChirho {
    AppendRequestChirho {
        op_chirho: LedgerOpChirho::EscrowHoldChirho {
            control_chirho: escrow_control_chirho(saga_tag_chirho, step_chirho),
        },
        legs_chirho: vec![escrow_leg_request_chirho(
            owner_chirho,
            LegDeltaChirho::HoldChirho,
            amount_chirho,
        )],
        idempotency_key_chirho: idem_chirho.to_owned(),
        provenance_chirho: None,
        attribution_chirho: AttributionChirho::CauserChirho {
            principal_chirho: owner_chirho.to_owned(),
        },
    }
}

fn escrow_release_request_chirho(
    owner_chirho: &str,
    amount_chirho: u64,
    saga_tag_chirho: &str,
    step_chirho: u32,
    idem_chirho: &str,
) -> AppendRequestChirho {
    AppendRequestChirho {
        op_chirho: LedgerOpChirho::EscrowReleaseChirho {
            control_chirho: escrow_control_chirho(saga_tag_chirho, step_chirho),
        },
        legs_chirho: vec![escrow_leg_request_chirho(
            owner_chirho,
            LegDeltaChirho::ReleaseChirho,
            amount_chirho,
        )],
        idempotency_key_chirho: idem_chirho.to_owned(),
        provenance_chirho: None,
        attribution_chirho: AttributionChirho::CauserChirho {
            principal_chirho: owner_chirho.to_owned(),
        },
    }
}

fn escrow_finalize_request_chirho(
    owner_chirho: &str,
    settlement_chirho: &str,
    amount_chirho: u64,
    saga_tag_chirho: &str,
    step_chirho: u32,
    idem_chirho: &str,
) -> AppendRequestChirho {
    AppendRequestChirho {
        op_chirho: LedgerOpChirho::EscrowFinalizeChirho {
            control_chirho: escrow_control_chirho(saga_tag_chirho, step_chirho),
        },
        legs_chirho: vec![
            escrow_leg_request_chirho(owner_chirho, LegDeltaChirho::FinalizeChirho, amount_chirho),
            escrow_leg_request_chirho(
                settlement_chirho,
                LegDeltaChirho::CreditChirho,
                amount_chirho,
            ),
        ],
        idempotency_key_chirho: idem_chirho.to_owned(),
        provenance_chirho: None,
        attribution_chirho: AttributionChirho::CauserChirho {
            principal_chirho: owner_chirho.to_owned(),
        },
    }
}

/// A funded engine: issuer minted 500, alice transferred 30 spendable.
fn funded_escrow_engine_chirho(harness_chirho: &HarnessChirho) -> LedgerJournalChirho<'_> {
    let mut engine_chirho = LedgerJournalChirho::create_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        harness_chirho.cluster_chirho(),
        1,
    )
    .unwrap();
    harness_chirho.clock_chirho.now_ms_chirho.set(1_100);
    engine_chirho
        .append_chirho(mint_request_chirho("issuer-chirho", 500, "idem-esc-mint"))
        .unwrap();
    engine_chirho
        .append_chirho(transfer_request_chirho(
            "issuer-chirho",
            "alice-chirho",
            30,
            "idem-esc-fund",
        ))
        .unwrap();
    engine_chirho
}

fn signed_effect_intent_line_chirho(
    engine_chirho: &LedgerJournalChirho<'_>,
    signer_chirho: &dyn EffectIntentSignerPortChirho,
) -> (EffectIntentChirho, String) {
    let intent_chirho = sign_effect_intent_chirho(
        EffectIntentChirho {
            schema_chirho: EFFECT_INTENT_SCHEMA_V1_CHIRHO.to_owned(),
            journal_cut_chirho: engine_chirho.effect_intent_cut_chirho(),
            contract_set_digest_chirho: DigestChirho(DIGEST_A_CHIRHO.to_owned()),
            door_chirho: serde_json::from_value(serde_json::json!({
                "effect_node_chirho": DIGEST_B_CHIRHO,
                "capability_fingerprint_chirho": DIGEST_C_CHIRHO,
            }))
            .unwrap(),
            reversion_contract_digest_chirho: DigestChirho(DIGEST_D_CHIRHO.to_owned()),
            request_ref_chirho: DigestChirho(DIGEST_A_CHIRHO.to_owned()),
            request_context_ref_chirho: DigestChirho(DIGEST_B_CHIRHO.to_owned()),
            evidence_refs_chirho: vec![DigestChirho(DIGEST_C_CHIRHO.to_owned())],
            resolved_price_chirho: AssetOpChirho {
                amount_chirho: 10,
                kind_id_chirho: MONEY_KIND_CHIRHO.into(),
                kind_policy_ref_chirho: AssetKindRefChirho(DigestChirho(
                    MONEY_POLICY_REF_CHIRHO.to_owned(),
                )),
                rounding_chirho: RoundingChirho::ExactChirho,
            },
            payer_account_chirho: LogIdChirho::new_chirho("alice-chirho", MONEY_KIND_CHIRHO),
            effect_step_chirho: 7,
            attribution_chirho: AttributionChirho::CauserChirho {
                principal_chirho: "alice-chirho".to_owned(),
            },
            original_effect_key_chirho: None,
            sig_chirho: String::new(),
            key_id_chirho: String::new(),
        },
        signer_chirho,
    )
    .unwrap();
    let line_chirho = canonical_effect_intent_line_chirho(&intent_chirho).unwrap();
    (intent_chirho, line_chirho)
}

#[test]
fn reserved_intent_namespace_requires_verified_door_and_replays_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let mut engine_chirho = funded_escrow_engine_chirho(&harness_chirho);
    let intent_signer_chirho = FakeEffectIntentSignerChirho {
        root_chirho: "effect-intent-root-chirho",
    };
    let (intent_chirho, line_chirho) =
        signed_effect_intent_line_chirho(&engine_chirho, &intent_signer_chirho);
    let intent_key_chirho = effect_intent_key_chirho(&intent_chirho).unwrap();

    for reserved_key_chirho in [
        intent_key_chirho.clone(),
        format!("{EFFECT_INTENT_KEY_PREFIX_CHIRHO}XYZ"),
    ] {
        assert!(matches!(
            engine_chirho.append_chirho(escrow_hold_request_chirho(
                "alice-chirho",
                10,
                "generic",
                7,
                &reserved_key_chirho,
            )),
            Err(JournalErrorChirho::EffectIntentChirho { .. })
        ));
    }

    let receipt_chirho = engine_chirho
        .append_effect_intent_chirho(&line_chirho, &intent_signer_chirho)
        .expect("verified intent derives and admits its Hold");
    assert_eq!(receipt_chirho.seq_chirho, 3);
    assert!(engine_chirho
        .active_holds_chirho()
        .keys()
        .any(|key_chirho| {
            key_chirho.account_chirho == intent_chirho.payer_account_chirho
                && key_chirho.saga_id_chirho.0
                    == intent_key_chirho[EFFECT_INTENT_KEY_PREFIX_CHIRHO.len()..]
                && key_chirho.step_chirho == intent_chirho.effect_step_chirho
        }));
    assert_eq!(
        engine_chirho
            .append_effect_intent_chirho(&line_chirho, &intent_signer_chirho)
            .expect("in-window retry returns the original receipt"),
        receipt_chirho
    );

    drop(engine_chirho);
    let mut reopened_chirho = LedgerJournalChirho::open_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        &harness_chirho.cluster_chirho(),
    )
    .expect("well-formed reserved K is rebuilt under ordinary chain trust");
    assert_eq!(
        reopened_chirho
            .append_effect_intent_chirho(&line_chirho, &intent_signer_chirho)
            .expect("full replay rebuilds the original receipt coordinates"),
        receipt_chirho
    );
}

#[test]
fn receipt_window_retains_equality_and_live_hold_then_stale_refuses_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let mut engine_chirho = funded_escrow_engine_chirho(&harness_chirho);
    let signer_chirho = FakeEffectIntentSignerChirho {
        root_chirho: "effect-intent-root-chirho",
    };
    let (intent_chirho, line_chirho) =
        signed_effect_intent_line_chirho(&engine_chirho, &signer_chirho);
    let intent_ref_chirho = effect_intent_ref_chirho(&intent_chirho).unwrap();
    let receipt_chirho = engine_chirho
        .append_effect_intent_chirho(&line_chirho, &signer_chirho)
        .unwrap();

    // Receipt committed at physical HLC 1100; age == horizon 1000 MUST remain retained.
    harness_chirho.clock_chirho.now_ms_chirho.set(2_100);
    engine_chirho
        .append_chirho(escrow_hold_request_chirho(
            "alice-chirho",
            1,
            "advance-equality",
            8,
            "idem-advance-equality-chirho",
        ))
        .unwrap();
    assert_eq!(
        engine_chirho
            .append_effect_intent_chirho(&line_chirho, &signer_chirho)
            .expect("strictly-older means equality stays retained"),
        receipt_chirho
    );

    // One millisecond past the horizon MUST NOT prune an unresolved effect: the live Hold keeps
    // its intent receipt visible to fsck and dedup-protected regardless of age.
    harness_chirho.clock_chirho.now_ms_chirho.set(2_101);
    engine_chirho
        .append_chirho(escrow_hold_request_chirho(
            "alice-chirho",
            1,
            "advance-stale",
            9,
            "idem-advance-stale-chirho",
        ))
        .unwrap();
    assert_eq!(
        engine_chirho
            .append_effect_intent_chirho(&line_chirho, &signer_chirho)
            .expect("a live Hold keeps its old receipt retained"),
        receipt_chirho
    );

    // Once the exact Hold resolves, the same strictly-older receipt may prune. Its next retry is
    // named StaleIntent BEFORE exact-cut/builder-fold checks and cannot be re-applied.
    engine_chirho
        .append_chirho(AppendRequestChirho {
            op_chirho: LedgerOpChirho::EscrowReleaseChirho {
                control_chirho: EscrowControlChirho {
                    saga_id_chirho: intent_ref_chirho,
                    step_chirho: intent_chirho.effect_step_chirho,
                },
            },
            legs_chirho: vec![escrow_leg_request_chirho(
                "alice-chirho",
                LegDeltaChirho::ReleaseChirho,
                intent_chirho.resolved_price_chirho.amount_chirho,
            )],
            idempotency_key_chirho: "idem-resolve-old-effect-hold-chirho".to_owned(),
            provenance_chirho: None,
            attribution_chirho: intent_chirho.attribution_chirho.clone(),
        })
        .unwrap();
    let hold_count_before_chirho = engine_chirho.active_holds_chirho().len();
    assert!(matches!(
        engine_chirho.append_effect_intent_chirho(&line_chirho, &signer_chirho),
        Err(JournalErrorChirho::StaleIntentChirho {
            age_ms_chirho: 1_001,
            idempotency_horizon_ms_chirho: 1_000,
            ..
        })
    ));
    assert_eq!(
        engine_chirho.active_holds_chirho().len(),
        hold_count_before_chirho,
        "stale refusal happens before any fold/state effect"
    );
}

#[test]
fn superseded_receipt_uses_the_longer_current_window_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let extending_registry_chirho = ExtendingMoneyRegistryChirho {
        superseded_chirho: Cell::new(false),
    };
    let ports_chirho = JournalPortsChirho {
        kind_registry_chirho: &extending_registry_chirho,
        ..harness_chirho.ports_chirho()
    };
    let mut engine_chirho = LedgerJournalChirho::create_chirho(
        ports_chirho,
        harness_chirho.path_chirho(),
        harness_chirho.cluster_chirho(),
        1,
    )
    .unwrap();
    harness_chirho.clock_chirho.now_ms_chirho.set(1_100);
    engine_chirho
        .append_chirho(mint_request_chirho(
            "issuer-chirho",
            500,
            "idem-extend-mint",
        ))
        .unwrap();
    engine_chirho
        .append_chirho(transfer_request_chirho(
            "issuer-chirho",
            "alice-chirho",
            30,
            "idem-extend-fund",
        ))
        .unwrap();
    let signer_chirho = FakeEffectIntentSignerChirho {
        root_chirho: "effect-intent-root-chirho",
    };
    let (intent_chirho, line_chirho) =
        signed_effect_intent_line_chirho(&engine_chirho, &signer_chirho);
    let intent_ref_chirho = effect_intent_ref_chirho(&intent_chirho).unwrap();
    let receipt_chirho = engine_chirho
        .append_effect_intent_chirho(&line_chirho, &signer_chirho)
        .unwrap();

    // R1 is now superseded for admission, while retention resolves it to R2's longer CURRENT
    // horizon. The production registry twin pins the signed amend and downgrade-refusal halves.
    extending_registry_chirho.superseded_chirho.set(true);
    harness_chirho.clock_chirho.now_ms_chirho.set(1_300);
    let mut equality_advance_chirho = escrow_hold_request_chirho(
        "alice-chirho",
        1,
        "extended-equality",
        10,
        "idem-extended-equality-chirho",
    );
    equality_advance_chirho.legs_chirho[0].kind_policy_ref_chirho =
        AssetKindRefChirho(DigestChirho(MONEY_POLICY_REF_V2_CHIRHO.to_owned()));
    engine_chirho
        .append_chirho(equality_advance_chirho)
        .unwrap();
    assert_eq!(
        engine_chirho
            .append_effect_intent_chirho(&line_chirho, &signer_chirho)
            .expect("R2 extends R1 retention through the equality boundary"),
        receipt_chirho
    );

    let mut release_leg_chirho = escrow_leg_request_chirho(
        "alice-chirho",
        LegDeltaChirho::ReleaseChirho,
        intent_chirho.resolved_price_chirho.amount_chirho,
    );
    release_leg_chirho.kind_policy_ref_chirho =
        AssetKindRefChirho(DigestChirho(MONEY_POLICY_REF_V2_CHIRHO.to_owned()));
    engine_chirho
        .append_chirho(AppendRequestChirho {
            op_chirho: LedgerOpChirho::EscrowReleaseChirho {
                control_chirho: EscrowControlChirho {
                    saga_id_chirho: intent_ref_chirho,
                    step_chirho: intent_chirho.effect_step_chirho,
                },
            },
            legs_chirho: vec![release_leg_chirho],
            idempotency_key_chirho: "idem-resolve-extended-effect-hold-chirho".to_owned(),
            provenance_chirho: None,
            attribution_chirho: intent_chirho.attribution_chirho.clone(),
        })
        .unwrap();

    harness_chirho.clock_chirho.now_ms_chirho.set(1_301);
    let mut stale_advance_chirho = escrow_hold_request_chirho(
        "alice-chirho",
        1,
        "extended-stale",
        11,
        "idem-extended-stale-chirho",
    );
    stale_advance_chirho.legs_chirho[0].kind_policy_ref_chirho =
        AssetKindRefChirho(DigestChirho(MONEY_POLICY_REF_V2_CHIRHO.to_owned()));
    engine_chirho.append_chirho(stale_advance_chirho).unwrap();
    assert!(matches!(
        engine_chirho.append_effect_intent_chirho(&line_chirho, &signer_chirho),
        Err(JournalErrorChirho::StaleIntentChirho {
            age_ms_chirho: 201,
            idempotency_horizon_ms_chirho: 200,
            ..
        })
    ));
}

#[test]
fn effect_intent_requires_bounded_policy_before_storage_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let unbounded_registry_chirho = UnboundedMoneyRegistryChirho;
    let base_ports_chirho = harness_chirho.ports_chirho();
    let ports_chirho = JournalPortsChirho {
        kind_registry_chirho: &unbounded_registry_chirho,
        ..base_ports_chirho
    };
    let mut engine_chirho = LedgerJournalChirho::create_chirho(
        ports_chirho,
        harness_chirho.path_chirho(),
        harness_chirho.cluster_chirho(),
        1,
    )
    .unwrap();
    harness_chirho.clock_chirho.now_ms_chirho.set(1_100);
    engine_chirho
        .append_chirho(mint_request_chirho(
            "issuer-chirho",
            500,
            "idem-unbounded-mint",
        ))
        .unwrap();
    engine_chirho
        .append_chirho(transfer_request_chirho(
            "issuer-chirho",
            "alice-chirho",
            30,
            "idem-unbounded-fund",
        ))
        .unwrap();
    let signer_chirho = FakeEffectIntentSignerChirho {
        root_chirho: "effect-intent-root-chirho",
    };
    let (_intent_chirho, line_chirho) =
        signed_effect_intent_line_chirho(&engine_chirho, &signer_chirho);
    let tail_before_chirho = engine_chirho.tail_chirho().0;
    assert!(matches!(
        engine_chirho.append_effect_intent_chirho(&line_chirho, &signer_chirho),
        Err(JournalErrorChirho::EffectIntentChirho { .. })
    ));
    assert_eq!(engine_chirho.tail_chirho().0, tail_before_chirho);
    assert!(engine_chirho.active_holds_chirho().is_empty());
}

#[test]
fn receipt_sidecar_migrates_by_full_replay_then_fast_opens_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let sidecar_path_chirho = StoragePathChirho(format!(
        "{}.head-checkpoint-chirho",
        harness_chirho.path_chirho().0
    ));
    let mut engine_chirho = funded_escrow_engine_chirho(&harness_chirho);

    // Empty-map identity: the new optional field is absent from both canonical bytes and the
    // signed message, preserving the pre-window sidecar bytes/signature exactly.
    engine_chirho.write_head_checkpoint_chirho().unwrap();
    let pre_window_bytes_chirho = harness_chirho
        .storage_chirho
        .read_all_chirho(&sidecar_path_chirho)
        .unwrap()
        .unwrap();
    let pre_window_text_chirho = String::from_utf8(pre_window_bytes_chirho).unwrap();
    assert!(!pre_window_text_chirho.contains("effect_receipt_window_chirho"));
    let pre_window_checkpoint_chirho =
        parse_head_checkpoint_chirho(pre_window_text_chirho.as_bytes()).unwrap();
    let pre_window_signing_chirho = String::from_utf8(
        pre_window_checkpoint_chirho
            .signing_message_chirho()
            .unwrap(),
    )
    .unwrap();
    assert!(harness_chirho.signer_chirho.verify_chirho(
        &pre_window_signing_chirho,
        &pre_window_checkpoint_chirho.sig_chirho
    ));

    let signer_chirho = FakeEffectIntentSignerChirho {
        root_chirho: "effect-intent-root-chirho",
    };
    let (intent_chirho, line_chirho) =
        signed_effect_intent_line_chirho(&engine_chirho, &signer_chirho);
    let intent_key_chirho = effect_intent_key_chirho(&intent_chirho).unwrap();
    let receipt_chirho = engine_chirho
        .append_effect_intent_chirho(&line_chirho, &signer_chirho)
        .unwrap();
    engine_chirho.write_head_checkpoint_chirho().unwrap();
    let two_set_bytes_chirho = harness_chirho
        .storage_chirho
        .read_all_chirho(&sidecar_path_chirho)
        .unwrap()
        .unwrap();
    assert!(
        !String::from_utf8(two_set_bytes_chirho.clone())
            .unwrap()
            .contains("terminal_outcome_ref_chirho"),
        "pre-terminal receipt entries keep their canonical checkpoint bytes"
    );
    let mut pre_migration_checkpoint_chirho =
        parse_head_checkpoint_chirho(&two_set_bytes_chirho).unwrap();
    assert!(pre_migration_checkpoint_chirho
        .effect_receipt_window_chirho
        .contains_key(&intent_key_chirho));

    // Synthesize the signed pre-window shape: move the reserved key back into the old single set
    // and omit the new map. It is cryptographically valid but lacks receipt coordinates.
    pre_migration_checkpoint_chirho
        .effect_receipt_window_chirho
        .remove(&intent_key_chirho)
        .unwrap();
    pre_migration_checkpoint_chirho
        .idempotency_window_chirho
        .insert(intent_key_chirho.clone());
    pre_migration_checkpoint_chirho.sig_chirho.clear();
    let signing_line_chirho = String::from_utf8(
        pre_migration_checkpoint_chirho
            .signing_message_chirho()
            .unwrap(),
    )
    .unwrap();
    pre_migration_checkpoint_chirho.sig_chirho = harness_chirho
        .signer_chirho
        .sign_chirho(&signing_line_chirho)
        .unwrap();
    let pre_migration_bytes_chirho =
        canonical_head_checkpoint_bytes_chirho(&pre_migration_checkpoint_chirho).unwrap();
    assert!(!String::from_utf8(pre_migration_bytes_chirho.clone())
        .unwrap()
        .contains("effect_receipt_window_chirho"));
    harness_chirho
        .storage_chirho
        .atomic_write_chirho(&sidecar_path_chirho, &pre_migration_bytes_chirho)
        .unwrap();
    drop(engine_chirho);

    let mut migrated_chirho = LedgerJournalChirho::open_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        &harness_chirho.cluster_chirho(),
    )
    .unwrap();
    assert!(
        !migrated_chirho.last_open_was_fast_chirho(),
        "reserved key in the old set forces structural full replay"
    );
    assert_eq!(
        migrated_chirho
            .append_effect_intent_chirho(&line_chirho, &signer_chirho)
            .unwrap(),
        receipt_chirho
    );

    migrated_chirho.write_head_checkpoint_chirho().unwrap();
    drop(migrated_chirho);
    let mut fast_chirho = LedgerJournalChirho::open_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        &harness_chirho.cluster_chirho(),
    )
    .unwrap();
    assert!(fast_chirho.last_open_was_fast_chirho());
    assert_eq!(
        fast_chirho
            .append_effect_intent_chirho(&line_chirho, &signer_chirho)
            .unwrap(),
        receipt_chirho
    );
}

#[test]
fn intent_root_and_current_cut_fail_before_any_hold_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let mut engine_chirho = funded_escrow_engine_chirho(&harness_chirho);
    let signer_chirho = FakeEffectIntentSignerChirho {
        root_chirho: "effect-intent-root-chirho",
    };
    let (_intent_chirho, line_chirho) =
        signed_effect_intent_line_chirho(&engine_chirho, &signer_chirho);
    assert!(matches!(
        engine_chirho.append_effect_intent_chirho(
            &line_chirho,
            &FakeEffectIntentSignerChirho {
                root_chirho: "foreign-intent-root-chirho"
            },
        ),
        Err(JournalErrorChirho::EffectIntentChirho { .. })
    ));
    engine_chirho
        .append_chirho(escrow_hold_request_chirho(
            "alice-chirho",
            1,
            "intervening",
            9,
            "idem-intervening-chirho",
        ))
        .unwrap();
    assert!(matches!(
        engine_chirho.append_effect_intent_chirho(&line_chirho, &signer_chirho),
        Err(JournalErrorChirho::EffectIntentChirho { .. })
    ));
}

#[test]
fn malformed_reserved_key_in_colluding_signed_history_fails_load_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let mut engine_chirho = funded_escrow_engine_chirho(&harness_chirho);
    engine_chirho
        .append_chirho(escrow_hold_request_chirho(
            "alice-chirho",
            1,
            "malformed-history",
            5,
            "ordinary-before-forge-chirho",
        ))
        .unwrap();
    drop(engine_chirho);

    let path_chirho = harness_chirho.path_chirho();
    let bytes_chirho = harness_chirho
        .storage_chirho
        .read_all_chirho(&path_chirho)
        .unwrap()
        .unwrap();
    let text_chirho = String::from_utf8(bytes_chirho).unwrap();
    let mut lines_chirho: Vec<String> = text_chirho
        .strip_suffix('\n')
        .unwrap()
        .split('\n')
        .map(str::to_owned)
        .collect();
    let mut tail_chirho =
        match parse_canonical_ledger_journal_line_chirho(lines_chirho.last().unwrap()).unwrap() {
            LedgerJournalLineChirho::RecordChirho(record_chirho) => record_chirho,
            LedgerJournalLineChirho::GenesisChirho(_) => panic!("funded journal has a record tail"),
        };
    tail_chirho.idempotency_key_chirho = format!("{EFFECT_INTENT_KEY_PREFIX_CHIRHO}XYZ");
    tail_chirho.sig_chirho.clear();
    tail_chirho.sig_chirho = harness_chirho
        .signer_chirho
        .sign_chirho(&ledger_record_signed_content_line_chirho(&tail_chirho).unwrap())
        .unwrap();
    *lines_chirho.last_mut().unwrap() = canonical_ledger_record_line_chirho(&tail_chirho).unwrap();
    let forged_chirho = format!("{}\n", lines_chirho.join("\n"));
    harness_chirho
        .storage_chirho
        .atomic_write_chirho(&path_chirho, forged_chirho.as_bytes())
        .unwrap();

    assert!(matches!(
        LedgerJournalChirho::open_chirho(
            harness_chirho.ports_chirho(),
            path_chirho,
            &harness_chirho.cluster_chirho(),
        ),
        Err(JournalErrorChirho::ChainChirho { detail_chirho })
            if detail_chirho.contains("malformed reserved CF3 intent key")
    ));
}

#[test]
fn duplicate_reserved_key_in_colluding_signed_history_fails_before_fold_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let mut engine_chirho = funded_escrow_engine_chirho(&harness_chirho);
    let signer_chirho = FakeEffectIntentSignerChirho {
        root_chirho: "effect-intent-root-chirho",
    };
    let (_intent_chirho, line_chirho) =
        signed_effect_intent_line_chirho(&engine_chirho, &signer_chirho);
    engine_chirho
        .append_effect_intent_chirho(&line_chirho, &signer_chirho)
        .unwrap();
    drop(engine_chirho);

    let path_chirho = harness_chirho.path_chirho();
    let bytes_chirho = harness_chirho
        .storage_chirho
        .read_all_chirho(&path_chirho)
        .unwrap()
        .unwrap();
    let text_chirho = String::from_utf8(bytes_chirho).unwrap();
    let tail_line_chirho = text_chirho.lines().last().unwrap();
    let mut duplicate_chirho =
        match parse_canonical_ledger_journal_line_chirho(tail_line_chirho).unwrap() {
            LedgerJournalLineChirho::RecordChirho(record_chirho) => record_chirho,
            LedgerJournalLineChirho::GenesisChirho(_) => panic!("intent append is a record"),
        };
    duplicate_chirho.seq_chirho += 1;
    duplicate_chirho.prev_chirho = stored_line_digest_chirho(tail_line_chirho);
    duplicate_chirho.hlc_chirho.logical_chirho += 1;
    duplicate_chirho.legs_chirho[0].post_chirho.held_chirho +=
        duplicate_chirho.legs_chirho[0].amount_chirho;
    duplicate_chirho.sig_chirho.clear();
    duplicate_chirho.sig_chirho = harness_chirho
        .signer_chirho
        .sign_chirho(&ledger_record_signed_content_line_chirho(&duplicate_chirho).unwrap())
        .unwrap();
    let duplicate_line_chirho = canonical_ledger_record_line_chirho(&duplicate_chirho).unwrap();
    harness_chirho
        .storage_chirho
        .append_durable_chirho(
            &path_chirho,
            format!("{duplicate_line_chirho}\n").as_bytes(),
        )
        .unwrap();

    assert!(matches!(
        LedgerJournalChirho::open_chirho(
            harness_chirho.ports_chirho(),
            path_chirho,
            &harness_chirho.cluster_chirho(),
        ),
        Err(JournalErrorChirho::ChainChirho { detail_chirho })
            if detail_chirho.contains("duplicate reserved CF3 intent key")
    ));
}

#[test]
fn escrow_hold_release_lifecycle_survives_reopen_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let mut engine_chirho = funded_escrow_engine_chirho(&harness_chirho);
    engine_chirho
        .append_chirho(escrow_hold_request_chirho(
            "alice-chirho",
            10,
            "a",
            1,
            "idem-esc-h1",
        ))
        .unwrap();
    // The unconsumed key refuses a duplicate at the LIVE surface...
    assert!(matches!(
        engine_chirho.append_chirho(escrow_hold_request_chirho(
            "alice-chirho",
            5,
            "a",
            1,
            "idem-esc-h1-dup",
        )),
        Err(JournalErrorChirho::AdmissionChirho {
            reject_chirho: AdmissionRejectChirho::DuplicateEscrowHoldChirho
        })
    ));
    // ...release consumes it, and the SAME key holds again (freed identity, F4 floor intact).
    engine_chirho
        .append_chirho(escrow_release_request_chirho(
            "alice-chirho",
            10,
            "a",
            1,
            "idem-esc-r1",
        ))
        .unwrap();
    engine_chirho
        .append_chirho(escrow_hold_request_chirho(
            "alice-chirho",
            12,
            "a",
            1,
            "idem-esc-h2",
        ))
        .unwrap();
    drop(engine_chirho);
    // REOPEN (full replay): the rebuilt index still knows the live hold and its exact amount.
    let mut reopened_chirho = LedgerJournalChirho::open_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        &harness_chirho.cluster_chirho(),
    )
    .unwrap();
    assert!(matches!(
        reopened_chirho.append_chirho(escrow_hold_request_chirho(
            "alice-chirho",
            3,
            "a",
            1,
            "idem-esc-h3",
        )),
        Err(JournalErrorChirho::AdmissionChirho {
            reject_chirho: AdmissionRejectChirho::DuplicateEscrowHoldChirho
        })
    ));
    assert!(matches!(
        reopened_chirho.append_chirho(escrow_release_request_chirho(
            "alice-chirho",
            10,
            "a",
            1,
            "idem-esc-r-stale",
        )),
        Err(JournalErrorChirho::AdmissionChirho {
            reject_chirho: AdmissionRejectChirho::UnknownEscrowHoldChirho
        })
    ));
    reopened_chirho
        .append_chirho(escrow_release_request_chirho(
            "alice-chirho",
            12,
            "a",
            1,
            "idem-esc-r2",
        ))
        .expect("the replay-rebuilt index carries the exact held amount");
}

#[test]
fn escrow_finalize_settles_to_the_designated_account_chirho() {
    let mut harness_chirho = HarnessChirho::new_chirho();
    harness_chirho.registry_chirho.settlement_owner_chirho = Some("bob-chirho".to_owned());
    let mut engine_chirho = funded_escrow_engine_chirho(&harness_chirho);
    // TWO live holds: saga b step 1 (the one we settle) and saga b2 step 1 (the decoy funder —
    // it keeps alice's held balance high enough that a double-consume of b/1 stays FOLD-PLAUSIBLE,
    // so only the escrow INDEX law can refuse it; an arithmetic underflow can never mask 9b here).
    engine_chirho
        .append_chirho(escrow_hold_request_chirho(
            "alice-chirho",
            10,
            "b",
            1,
            "idem-fin-h1",
        ))
        .unwrap();
    engine_chirho
        .append_chirho(escrow_hold_request_chirho(
            "alice-chirho",
            10,
            "b2",
            1,
            "idem-fin-h2",
        ))
        .unwrap();
    engine_chirho
        .append_chirho(escrow_finalize_request_chirho(
            "alice-chirho",
            "bob-chirho",
            10,
            "b",
            1,
            "idem-fin-f1",
        ))
        .expect("finalize to the designated settlement account");
    // The hold is CONSUMED: the fold-plausible second settlement refuses ON THE INDEX LAW.
    assert!(matches!(
        engine_chirho.append_chirho(escrow_finalize_request_chirho(
            "alice-chirho",
            "bob-chirho",
            10,
            "b",
            1,
            "idem-fin-f2",
        )),
        Err(JournalErrorChirho::AdmissionChirho {
            reject_chirho: AdmissionRejectChirho::UnknownEscrowHoldChirho
        })
    ));
    // Bob RECEIVED settled value exactly once: he can move 10 out (behavioral balance proof).
    engine_chirho
        .append_chirho(transfer_request_chirho(
            "bob-chirho",
            "issuer-chirho",
            10,
            "idem-fin-spend",
        ))
        .expect("settlement credit is spendable by the designated account");
    drop(engine_chirho);
    // Replay equivalence: reopen agrees b/1 is consumed (still fold-plausible via b2/1)...
    let mut reopened_chirho = LedgerJournalChirho::open_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        &harness_chirho.cluster_chirho(),
    )
    .unwrap();
    assert!(matches!(
        reopened_chirho.append_chirho(escrow_release_request_chirho(
            "alice-chirho",
            10,
            "b",
            1,
            "idem-fin-r-stale",
        )),
        Err(JournalErrorChirho::AdmissionChirho {
            reject_chirho: AdmissionRejectChirho::UnknownEscrowHoldChirho
        })
    ));
    // ...while the decoy hold itself releases cleanly.
    reopened_chirho
        .append_chirho(escrow_release_request_chirho(
            "alice-chirho",
            10,
            "b2",
            1,
            "idem-fin-r2",
        ))
        .expect("the untouched saga hold releases after reopen");
}

#[test]
fn forged_release_of_unknown_hold_fails_closed_at_load_chirho() {
    // P2's load-side twin: a COLLUDING-SIGNER forgery (chain-valid, sig-valid, FOLD-TRUE) that
    // releases a step nobody held must die in replay at the escrow transition — admission is
    // bypassed by construction, so only the journal's own index law can catch it.
    let harness_chirho = HarnessChirho::new_chirho();
    let mut engine_chirho = funded_escrow_engine_chirho(&harness_chirho);
    engine_chirho
        .append_chirho(escrow_hold_request_chirho(
            "alice-chirho",
            20,
            "c",
            1,
            "idem-forge-h1",
        ))
        .unwrap();
    drop(engine_chirho);
    let log_bytes_chirho = harness_chirho
        .storage_chirho
        .read_all_chirho(&harness_chirho.path_chirho())
        .unwrap()
        .unwrap();
    let log_text_chirho = String::from_utf8(log_bytes_chirho).unwrap();
    let tail_line_chirho = log_text_chirho.lines().last().unwrap().to_owned();
    let template_chirho: LedgerRecordChirho = serde_json::from_str(&tail_line_chirho).unwrap();
    let mut forged_chirho = template_chirho.clone();
    forged_chirho.seq_chirho = template_chirho.seq_chirho + 1;
    forged_chirho.prev_chirho = stored_line_digest_chirho(&tail_line_chirho);
    forged_chirho.hlc_chirho.logical_chirho += 1;
    forged_chirho.op_chirho = LedgerOpChirho::EscrowReleaseChirho {
        control_chirho: escrow_control_chirho("c", 2),
    };
    forged_chirho.idempotency_key_chirho = "idem-forged-release".to_owned();
    let template_leg_chirho = &template_chirho.legs_chirho[0];
    forged_chirho.legs_chirho = vec![LedgerLegChirho {
        account_chirho: template_leg_chirho.account_chirho.clone(),
        kind_policy_ref_chirho: template_leg_chirho.kind_policy_ref_chirho.clone(),
        delta_chirho: LegDeltaChirho::ReleaseChirho,
        amount_chirho: 10,
        // Fold-true from the hold's post (30, 0, 20): release 10 lands at (30, 0, 10).
        post_chirho: LegPostStateChirho {
            credits_total_chirho: 30,
            debits_total_chirho: 0,
            held_chirho: 10,
        },
        counterpart_chirho: None,
    }];
    forged_chirho.sig_chirho = String::new();
    let signed_content_chirho = ledger_record_signed_content_line_chirho(&forged_chirho).unwrap();
    forged_chirho.sig_chirho = harness_chirho
        .signer_chirho
        .sign_chirho(&signed_content_chirho)
        .unwrap();
    let forged_line_chirho = canonical_ledger_record_line_chirho(&forged_chirho).unwrap();
    let tampered_chirho = format!("{log_text_chirho}{forged_line_chirho}\n");
    harness_chirho
        .storage_chirho
        .atomic_write_chirho(&harness_chirho.path_chirho(), tampered_chirho.as_bytes())
        .unwrap();
    match LedgerJournalChirho::open_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        &harness_chirho.cluster_chirho(),
    ) {
        Err(JournalErrorChirho::ChainChirho { detail_chirho }) => assert!(
            detail_chirho.contains("no matching unconsumed hold"),
            "the forged release must die at the escrow transition: {detail_chirho}"
        ),
        Err(other_chirho) => {
            panic!("a forged unknown-hold release must fail at the escrow law: {other_chirho:?}")
        }
        Ok(_) => panic!("a forged unknown-hold release must fail the load closed"),
    }
}

#[test]
fn fast_open_restores_the_active_holds_index_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let mut engine_chirho = funded_escrow_engine_chirho(&harness_chirho);
    engine_chirho
        .append_chirho(escrow_hold_request_chirho(
            "alice-chirho",
            10,
            "d",
            1,
            "idem-fast-h1",
        ))
        .unwrap();
    engine_chirho.write_head_checkpoint_chirho().unwrap();
    drop(engine_chirho);
    let mut reopened_chirho = LedgerJournalChirho::open_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        &harness_chirho.cluster_chirho(),
    )
    .unwrap();
    assert!(
        reopened_chirho.last_open_was_fast_chirho(),
        "the checkpointed journal must take the FAST path for this twin to bind"
    );
    // The sidecar-restored index enforces both escrow laws without any replay.
    assert!(matches!(
        reopened_chirho.append_chirho(escrow_hold_request_chirho(
            "alice-chirho",
            5,
            "d",
            1,
            "idem-fast-h-dup",
        )),
        Err(JournalErrorChirho::AdmissionChirho {
            reject_chirho: AdmissionRejectChirho::DuplicateEscrowHoldChirho
        })
    ));
    reopened_chirho
        .append_chirho(escrow_release_request_chirho(
            "alice-chirho",
            10,
            "d",
            1,
            "idem-fast-r1",
        ))
        .expect("the sidecar-restored index carries the exact held amount");
}

/// #5028 hardening: a SAME-KEY retry of a consumed finalize surfaces the TYPED duplicate — the
/// idem pre-check runs before the builder fold, so the fold underflow (Arithmetic) can no longer
/// mask the honest crash-retry signal. (Different-key double-consume stays the index law's job —
/// the decoy test above.)
#[test]
fn same_key_finalize_retry_is_a_typed_duplicate_chirho() {
    let mut harness_chirho = HarnessChirho::new_chirho();
    harness_chirho.registry_chirho.settlement_owner_chirho = Some("bob-chirho".to_owned());
    let mut engine_chirho = funded_escrow_engine_chirho(&harness_chirho);
    engine_chirho
        .append_chirho(escrow_hold_request_chirho(
            "alice-chirho",
            10,
            "ik",
            1,
            "idem-ik-h1",
        ))
        .unwrap();
    engine_chirho
        .append_chirho(escrow_finalize_request_chirho(
            "alice-chirho",
            "bob-chirho",
            10,
            "ik",
            1,
            "idem-ik-f1",
        ))
        .unwrap();
    // The crash-retry: SAME request, SAME key — typed duplicate, never Arithmetic.
    assert!(matches!(
        engine_chirho.append_chirho(escrow_finalize_request_chirho(
            "alice-chirho",
            "bob-chirho",
            10,
            "ik",
            1,
            "idem-ik-f1",
        )),
        Err(JournalErrorChirho::AdmissionChirho {
            reject_chirho: AdmissionRejectChirho::IdempotencyDuplicateChirho
        })
    ));
}
