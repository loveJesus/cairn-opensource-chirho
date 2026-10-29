// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! F3 counterpart boundary negatives: compositional absence stays closed, while the independent
//! oracle still applies the standing per-kind conservation law to an otherwise valid boundary form.

use super::*;
use cairn_ledger_model_chirho::counterpart_chirho::{CounterpartClaimChirho, FinalBurnRefChirho};

#[test]
fn counterpart_transfer_oracle_admits_shape_while_absent_views_refuse_chirho() {
    // The independent oracle owns the amended §11.10 shape + arithmetic. B additionally requires
    // both injected F3 views; `None` must keep the authority row closed rather than default-opening.
    let fixture_chirho = FixtureChirho::new_chirho();
    let dst_chirho = account_chirho("bob-chirho", MONEY_KIND_CHIRHO);
    let mut credit_leg_chirho = leg_chirho(
        "bob-chirho",
        MONEY_KIND_CHIRHO,
        MONEY_REF_CHIRHO,
        LegDeltaChirho::CreditChirho,
        40,
        post_chirho(40, 0, 0),
    );
    credit_leg_chirho.counterpart_chirho = Some(dummy_counterpart_chirho(&dst_chirho));
    let legs_chirho = vec![
        leg_chirho(
            "alice-chirho",
            MONEY_KIND_CHIRHO,
            MONEY_REF_CHIRHO,
            LegDeltaChirho::DebitChirho,
            40,
            post_chirho(100, 40, 0),
        ),
        credit_leg_chirho,
    ];
    let record_chirho = record_chirho(LedgerOpChirho::TransferChirho, legs_chirho);
    assert_oracle_accepts_chirho(&[("alice-chirho", MONEY_KIND_CHIRHO, 100)], &record_chirho);
    assert_eq!(
        admit_chirho(&fixture_chirho.context_chirho(), record_chirho),
        Err(AdmissionRejectChirho::UnsupportedOperationChirho)
    );
}

#[test]
fn counterpart_transfer_cross_kind_refuses_per_kind_balance_chirho() {
    let dst_chirho = account_chirho("bob-chirho", POINTS_KIND_CHIRHO);
    let mut credit_leg_chirho = leg_chirho(
        "bob-chirho",
        POINTS_KIND_CHIRHO,
        POINTS_REF_CHIRHO,
        LegDeltaChirho::CreditChirho,
        40,
        post_chirho(40, 0, 0),
    );
    credit_leg_chirho.counterpart_chirho = Some(dummy_counterpart_chirho(&dst_chirho));
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
            credit_leg_chirho,
        ],
    );
    let mut oracle_chirho = seeded_oracle_chirho(&[("alice-chirho", MONEY_KIND_CHIRHO, 100)]);
    assert_eq!(
        oracle_chirho
            .apply_grammar_arithmetic_chirho(&record_chirho.legs_chirho, &record_chirho.op_chirho,),
        Err(RejectReasonChirho::NotBalancedChirho)
    );
}

fn dummy_counterpart_chirho(dst_chirho: &AccountIdChirho) -> CounterpartClaimChirho {
    let src_mg_chirho = MoneyGroupIdChirho("mg-src-chirho".into());
    let src_cl_chirho = ClusterIdChirho("cl-src-chirho".into());
    let src_digest_chirho = DigestChirho("burn-digest-chirho".into());
    let dst_mg_chirho = MoneyGroupIdChirho("mg-dst-chirho".into());
    let dst_cl_chirho = ClusterIdChirho("cl-dst-chirho".into());
    let channel_chirho = SettlementChannelIdChirho("chan-chirho".into());
    let nullifier_chirho = CounterpartNullifierChirho::derive_chirho(
        &src_mg_chirho,
        &src_cl_chirho,
        1,
        1,
        &src_digest_chirho,
        &dst_mg_chirho,
        &dst_cl_chirho,
        dst_chirho,
        &channel_chirho,
    );
    CounterpartClaimChirho {
        transfer_id_chirho: TransferIdChirho("t-chirho".into()),
        burn_chirho: FinalBurnRefChirho {
            source_money_group_chirho: src_mg_chirho,
            source_cluster_chirho: src_cl_chirho,
            source_epoch_chirho: 1,
            source_seq_chirho: 1,
            source_record_digest_chirho: src_digest_chirho,
            finality_proof_ref_chirho: DigestChirho("finality-chirho".into()),
        },
        amount_chirho: 40,
        kind_policy_ref_chirho: kind_ref_chirho(MONEY_REF_CHIRHO),
        src_chirho: account_chirho("alice-chirho", MONEY_KIND_CHIRHO),
        dst_money_group_chirho: dst_mg_chirho,
        dst_cluster_chirho: dst_cl_chirho,
        dst_chirho: dst_chirho.clone(),
        channel_chirho,
        nullifier_chirho,
    }
}
