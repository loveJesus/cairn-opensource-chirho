// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! CF2 escrow + F3a x-cluster admission REDs (split from admission_tests per the file-cap
//! signal): the escrow triple/five-way/settlement laws, and the counterpart laws i-v with the
//! thirteen single-dimension binding mutations over composed stub views.

use crate::admission_chirho::*;
use crate::admission_tests_chirho::{
    account_chirho, leg_chirho, post_chirho, record_chirho, FinalityStubsChirho, FixtureChirho,
    StubProofStoreChirho, StubSettlementAuthChirho, StubSourceRootsChirho, MONEY_KIND_CHIRHO,
    MONEY_POLICY_REF_CHIRHO,
};
use cairn_ledger_model_chirho::ids_chirho::*;
use cairn_ledger_model_chirho::record_chirho::*;

fn saga_chirho(tag_chirho: &str) -> DigestChirho {
    DigestChirho(format!("saga-{tag_chirho}-chirho"))
}

fn escrow_hold_record_chirho(
    owner_chirho: &str,
    amount_chirho: u64,
    saga_tag_chirho: &str,
    step_chirho: u32,
    post: LegPostStateChirho,
) -> LedgerRecordChirho {
    record_chirho(
        LedgerOpChirho::EscrowHoldChirho {
            control_chirho: EscrowControlChirho {
                saga_id_chirho: saga_chirho(saga_tag_chirho),
                step_chirho,
            },
        },
        vec![leg_chirho(
            owner_chirho,
            MONEY_KIND_CHIRHO,
            MONEY_POLICY_REF_CHIRHO,
            LegDeltaChirho::HoldChirho,
            amount_chirho,
            post,
        )],
    )
}

fn escrow_release_record_chirho(
    owner_chirho: &str,
    amount_chirho: u64,
    saga_tag_chirho: &str,
    step_chirho: u32,
    post: LegPostStateChirho,
) -> LedgerRecordChirho {
    record_chirho(
        LedgerOpChirho::EscrowReleaseChirho {
            control_chirho: EscrowControlChirho {
                saga_id_chirho: saga_chirho(saga_tag_chirho),
                step_chirho,
            },
        },
        vec![leg_chirho(
            owner_chirho,
            MONEY_KIND_CHIRHO,
            MONEY_POLICY_REF_CHIRHO,
            LegDeltaChirho::ReleaseChirho,
            amount_chirho,
            post,
        )],
    )
}

fn escrow_finalize_record_chirho(
    owner_chirho: &str,
    settlement_chirho: &str,
    amount_chirho: u64,
    saga_tag_chirho: &str,
    step_chirho: u32,
    finalize_post_chirho: LegPostStateChirho,
    credit_post_chirho: LegPostStateChirho,
) -> LedgerRecordChirho {
    record_chirho(
        LedgerOpChirho::EscrowFinalizeChirho {
            control_chirho: EscrowControlChirho {
                saga_id_chirho: saga_chirho(saga_tag_chirho),
                step_chirho,
            },
        },
        vec![
            leg_chirho(
                owner_chirho,
                MONEY_KIND_CHIRHO,
                MONEY_POLICY_REF_CHIRHO,
                LegDeltaChirho::FinalizeChirho,
                amount_chirho,
                finalize_post_chirho,
            ),
            leg_chirho(
                settlement_chirho,
                MONEY_KIND_CHIRHO,
                MONEY_POLICY_REF_CHIRHO,
                LegDeltaChirho::CreditChirho,
                amount_chirho,
                credit_post_chirho,
            ),
        ],
    )
}

/// Seeds one unconsumed hold — (alice, saga-a, step 1) for 10 — with the head state the fold
/// law implies (held 10 on top of the 100 credit baseline).
fn held_fixture_chirho() -> FixtureChirho {
    let mut fixture_chirho = FixtureChirho::new_chirho();
    fixture_chirho.head_states_chirho.insert(
        account_chirho("alice-chirho", MONEY_KIND_CHIRHO),
        post_chirho(100, 0, 10),
    );
    fixture_chirho.active_holds_chirho.insert(
        EscrowHoldKeyChirho {
            account_chirho: account_chirho("alice-chirho", MONEY_KIND_CHIRHO),
            saga_id_chirho: saga_chirho("a"),
            step_chirho: 1,
        },
        10,
    );
    fixture_chirho
}

#[test]
fn escrow_hold_refuses_exact_duplicate_key_admits_next_step_chirho() {
    // P3 BOTH WAYS: the EXACT (account, saga, step) triple refuses while it stays unconsumed...
    let fixture_chirho = held_fixture_chirho();
    assert!(matches!(
        admit_chirho(
            &fixture_chirho.context_chirho(),
            escrow_hold_record_chirho("alice-chirho", 5, "a", 1, post_chirho(100, 0, 15)),
        ),
        Err(AdmissionRejectChirho::DuplicateEscrowHoldChirho)
    ));
    // ...but the SAME saga at the NEXT step is a distinct hold and ADMITS (multi-step sagas).
    admit_chirho(
        &fixture_chirho.context_chirho(),
        escrow_hold_record_chirho("alice-chirho", 20, "a", 2, post_chirho(100, 0, 30)),
    )
    .expect("same saga, different step is a FRESH key (P3)");
    // A different saga at the taken step admits too — the triple is the whole identity.
    admit_chirho(
        &fixture_chirho.context_chirho(),
        escrow_hold_record_chirho("alice-chirho", 20, "b", 1, post_chirho(100, 0, 30)),
    )
    .expect("different saga at the same step is a fresh key");
}

#[test]
fn escrow_release_requires_the_exact_five_way_match_chirho() {
    let fixture_chirho = held_fixture_chirho();
    let context_chirho = fixture_chirho.context_chirho();
    // Wrong step, wrong saga, wrong amount, wrong account — each misses the unconsumed hold.
    for miss_chirho in [
        escrow_release_record_chirho("alice-chirho", 10, "a", 2, post_chirho(100, 0, 0)),
        escrow_release_record_chirho("alice-chirho", 10, "b", 1, post_chirho(100, 0, 0)),
        escrow_release_record_chirho("alice-chirho", 5, "a", 1, post_chirho(100, 0, 5)),
        escrow_release_record_chirho("carol-chirho", 10, "a", 1, post_chirho(0, 0, 0)),
    ] {
        assert!(matches!(
            admit_chirho(&context_chirho, miss_chirho),
            Err(AdmissionRejectChirho::UnknownEscrowHoldChirho)
        ));
    }
    // The exact five-way match ADMITS and the fold returns the held value to spendable.
    admit_chirho(
        &context_chirho,
        escrow_release_record_chirho("alice-chirho", 10, "a", 1, post_chirho(100, 0, 0)),
    )
    .expect("the exact five-way release match admits");
}

#[test]
fn escrow_finalize_binds_the_designated_settlement_account_chirho() {
    // Sub-ruling a: policy None = Finalize refuses — settlement is DESIGNATED, never elective.
    let none_fixture_chirho = held_fixture_chirho();
    assert!(matches!(
        admit_chirho(
            &none_fixture_chirho.context_chirho(),
            escrow_finalize_record_chirho(
                "alice-chirho",
                "carol-chirho",
                10,
                "a",
                1,
                post_chirho(100, 10, 0),
                post_chirho(10, 0, 0),
            ),
        ),
        Err(AdmissionRejectChirho::SettlementTargetMismatchChirho)
    ));
    // With a designated owner, crediting anyone ELSE refuses...
    let mut designated_fixture_chirho = held_fixture_chirho();
    designated_fixture_chirho
        .registry_chirho
        .policies_chirho
        .get_mut(&AssetKindRefChirho(DigestChirho(
            MONEY_POLICY_REF_CHIRHO.into(),
        )))
        .unwrap()
        .settlement_owner_chirho = Some("carol-chirho".to_owned());
    assert!(matches!(
        admit_chirho(
            &designated_fixture_chirho.context_chirho(),
            escrow_finalize_record_chirho(
                "alice-chirho",
                "bob-chirho",
                10,
                "a",
                1,
                post_chirho(100, 10, 0),
                post_chirho(10, 0, 0),
            ),
        ),
        Err(AdmissionRejectChirho::SettlementTargetMismatchChirho)
    ));
    // ...and the designated account ADMITS: hold consumed into a settlement credit.
    admit_chirho(
        &designated_fixture_chirho.context_chirho(),
        escrow_finalize_record_chirho(
            "alice-chirho",
            "carol-chirho",
            10,
            "a",
            1,
            post_chirho(100, 10, 0),
            post_chirho(10, 0, 0),
        ),
    )
    .expect("finalize to the designated settlement account admits");
}

// ==== F3a — the x-cluster counterpart laws (§11.8a, signed #5044/#5045/#5046) ====================

fn valid_finality_scenario_chirho() -> (FixtureChirho, LedgerRecordChirho) {
    use cairn_ledger_model_chirho::counterpart_chirho::{
        CounterpartClaimChirho, CounterpartNullifierChirho, FinalBurnRefChirho,
    };
    use cairn_ledger_model_chirho::finality_chirho::{
        canonical_finality_proof_line_chirho, derive_finality_proof_ref_chirho,
        finality_proof_signed_content_chirho, FinalityProofChirho, RetainedCutChirho,
        FINALITY_PROOF_SCHEMA_V1_CHIRHO,
    };
    let mut fixture_chirho = FixtureChirho::new_chirho();
    fixture_chirho
        .membership_chirho
        .members_chirho
        .insert("settlement-b-chirho".to_owned());
    fixture_chirho.head_states_chirho.insert(
        account_chirho("settlement-b-chirho", MONEY_KIND_CHIRHO),
        post_chirho(100, 0, 0),
    );
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
        burn_kind_policy_ref_chirho: AssetKindRefChirho(DigestChirho(
            MONEY_POLICY_REF_CHIRHO.into(),
        )),
        burn_src_chirho: account_chirho("carol-chirho", MONEY_KIND_CHIRHO),
        burn_dst_money_group_chirho: MoneyGroupIdChirho("mg-1-chirho".into()),
        burn_dst_cluster_chirho: ClusterIdChirho("cluster-fixture-chirho".into()),
        burn_dst_chirho: account_chirho("bob-chirho", MONEY_KIND_CHIRHO),
        burn_channel_chirho: SettlementChannelIdChirho("chan-1-chirho".into()),
        root_sig_chirho: String::new(),
    };
    let content_chirho = finality_proof_signed_content_chirho(&proof_chirho).unwrap();
    proof_chirho.root_sig_chirho = format!(
        "mg-root-sig-{}",
        &blake3::hash(content_chirho.as_bytes()).to_hex()[..16]
    );
    let proof_line_chirho = canonical_finality_proof_line_chirho(&proof_chirho).unwrap();
    let proof_ref_chirho = derive_finality_proof_ref_chirho(&proof_chirho).unwrap();
    let mut proofs_chirho = StubProofStoreChirho::default();
    proofs_chirho
        .proofs_chirho
        .insert(proof_ref_chirho.clone(), proof_line_chirho.into_bytes());
    fixture_chirho.finality_stubs_chirho = Some(FinalityStubsChirho {
        proofs_chirho,
        roots_chirho: StubSourceRootsChirho {
            money_group_chirho: "mg-1-chirho".into(),
        },
        authorizations_chirho: StubSettlementAuthChirho {
            transfer_chirho: "t-x-chirho".into(),
            channel_chirho: "chan-1-chirho".into(),
            settlement_owner_chirho: "settlement-b-chirho".into(),
        },
    });
    let claim_chirho = CounterpartClaimChirho {
        transfer_id_chirho: TransferIdChirho("t-x-chirho".into()),
        burn_chirho: FinalBurnRefChirho {
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
    );
    record_chirho.legs_chirho[1].counterpart_chirho = Some(claim_chirho);
    (fixture_chirho, record_chirho)
}

#[test]
fn counterpart_admits_with_full_evidence_and_absence_refuses_chirho() {
    let (fixture_chirho, record_chirho) = valid_finality_scenario_chirho();
    admit_chirho(&fixture_chirho.context_chirho(), record_chirho.clone())
        .expect("the fully-evidenced x-cluster credit admits (laws i-iv)");
    // Law v: the SAME record refuses Unsupported on a journal composed WITHOUT the views.
    let mut absent_chirho = valid_finality_scenario_chirho().0;
    absent_chirho.finality_stubs_chirho = None;
    assert!(matches!(
        admit_chirho(&absent_chirho.context_chirho(), record_chirho),
        Err(AdmissionRejectChirho::UnsupportedOperationChirho)
    ));
}

#[test]
fn counterpart_binding_skews_each_refuse_on_their_dimension_chirho() {
    // Missing proof.
    let (mut fixture_chirho, record_chirho) = valid_finality_scenario_chirho();
    fixture_chirho
        .finality_stubs_chirho
        .as_mut()
        .unwrap()
        .proofs_chirho
        .proofs_chirho
        .clear();
    assert!(matches!(
        admit_chirho(&fixture_chirho.context_chirho(), record_chirho),
        Err(AdmissionRejectChirho::CounterpartProofMissingChirho)
    ));
    // Tampered proof bytes (content-address mismatch).
    let (mut fixture_chirho, record_chirho) = valid_finality_scenario_chirho();
    {
        let proofs_chirho = &mut fixture_chirho
            .finality_stubs_chirho
            .as_mut()
            .unwrap()
            .proofs_chirho
            .proofs_chirho;
        let (key_chirho, mut bytes_chirho) = proofs_chirho
            .iter()
            .next()
            .map(|(k, v)| (k.clone(), v.clone()))
            .unwrap();
        let text_chirho = String::from_utf8(bytes_chirho.clone()).unwrap();
        bytes_chirho = text_chirho.replacen("40", "41", 1).into_bytes();
        proofs_chirho.insert(key_chirho, bytes_chirho);
    }
    assert!(matches!(
        admit_chirho(&fixture_chirho.context_chirho(), record_chirho),
        Err(AdmissionRejectChirho::CounterpartProofInvalidChirho { .. })
    ));
    // Wrong source money group (wrong root verifies nothing).
    let (mut fixture_chirho, record_chirho) = valid_finality_scenario_chirho();
    fixture_chirho
        .finality_stubs_chirho
        .as_mut()
        .unwrap()
        .roots_chirho
        .money_group_chirho = "mg-other-chirho".into();
    assert!(matches!(
        admit_chirho(&fixture_chirho.context_chirho(), record_chirho),
        Err(AdmissionRejectChirho::CounterpartProofInvalidChirho { .. })
    ));
    // Claim amount skew (leg binding).
    let (fixture_chirho, mut record_chirho) = valid_finality_scenario_chirho();
    record_chirho.legs_chirho[1]
        .counterpart_chirho
        .as_mut()
        .unwrap()
        .amount_chirho = 41;
    assert!(matches!(
        admit_chirho(&fixture_chirho.context_chirho(), record_chirho),
        Err(AdmissionRejectChirho::CounterpartBindingMismatchChirho { .. })
    ));
    // Wrong destination cluster.
    let (fixture_chirho, mut record_chirho) = valid_finality_scenario_chirho();
    record_chirho.legs_chirho[1]
        .counterpart_chirho
        .as_mut()
        .unwrap()
        .dst_cluster_chirho = ClusterIdChirho("cluster-elsewhere-chirho".into());
    assert!(matches!(
        admit_chirho(&fixture_chirho.context_chirho(), record_chirho),
        Err(AdmissionRejectChirho::CounterpartBindingMismatchChirho { .. })
    ));
    // Lying nullifier (chosen, not derived).
    let (fixture_chirho, mut record_chirho) = valid_finality_scenario_chirho();
    record_chirho.legs_chirho[1]
        .counterpart_chirho
        .as_mut()
        .unwrap()
        .nullifier_chirho =
        cairn_ledger_model_chirho::counterpart_chirho::CounterpartNullifierChirho(DigestChirho(
            "f".repeat(64),
        ));
    assert!(matches!(
        admit_chirho(&fixture_chirho.context_chirho(), record_chirho),
        Err(AdmissionRejectChirho::CounterpartNullifierMismatchChirho)
    ));
    // Consumed nullifier (the replay).
    let (mut fixture_chirho, record_chirho) = valid_finality_scenario_chirho();
    let nullifier_chirho = record_chirho.legs_chirho[1]
        .counterpart_chirho
        .as_ref()
        .unwrap()
        .nullifier_chirho
        .clone();
    fixture_chirho
        .consumed_nullifiers_chirho
        .insert(nullifier_chirho);
    assert!(matches!(
        admit_chirho(&fixture_chirho.context_chirho(), record_chirho),
        Err(AdmissionRejectChirho::CounterpartNullifierConsumedChirho)
    ));
    // Settlement authorization refused (wrong channel binding in the evidence view).
    let (mut fixture_chirho, record_chirho) = valid_finality_scenario_chirho();
    fixture_chirho
        .finality_stubs_chirho
        .as_mut()
        .unwrap()
        .authorizations_chirho
        .channel_chirho = "chan-other-chirho".into();
    assert!(matches!(
        admit_chirho(&fixture_chirho.context_chirho(), record_chirho),
        Err(AdmissionRejectChirho::SettlementAuthorizationRefusedChirho)
    ));
    // Bad shape: claim on the DEBIT leg.
    let (fixture_chirho, mut record_chirho) = valid_finality_scenario_chirho();
    let claim_chirho = record_chirho.legs_chirho[1].counterpart_chirho.take();
    record_chirho.legs_chirho[0].counterpart_chirho = claim_chirho;
    assert!(matches!(
        admit_chirho(&fixture_chirho.context_chirho(), record_chirho),
        Err(AdmissionRejectChirho::BadShapeChirho { .. })
    ));
}
