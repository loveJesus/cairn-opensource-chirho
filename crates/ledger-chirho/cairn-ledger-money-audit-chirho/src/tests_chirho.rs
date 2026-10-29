// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Reference-model money invariants over the RAW arithmetic/grammar checker: §11.2 per-kind
//! conservation, §11.3 fence + F4 spendable-floor, and the exhaustive §11.10 op->leg grammar-SHAPE.
//! Every apply goes through `apply_grammar_arithmetic_chirho`, which makes NO admission decision —
//! admission (membership / mint-burn authority / settlement-role / finality) is B's, tested by B's own
//! REDs. The B-vs-reference accept/reject differential is DEFERRED until `cairn-ledger-log-chirho`
//! owns the unforgeable admitted-record token (gpt #4486/#4487, claude #4488 — a public marker trait
//! is forgeable by orphan rules, so admission typing cannot be established in this crate).

use super::*;
use cairn_ledger_model_chirho::counterpart_chirho::{
    CounterpartClaimChirho, CounterpartNullifierChirho, FinalBurnRefChirho,
};
use cairn_ledger_model_chirho::ids_chirho::{
    AccountIdChirho, AssetKindRefChirho, ClusterIdChirho, DigestChirho, MoneyGroupIdChirho,
    SettlementChannelIdChirho, TransferIdChirho,
};
use cairn_ledger_model_chirho::record_chirho::{
    EscrowControlChirho, HlcChirho, LedgerLegChirho, LedgerOpChirho, LegDeltaChirho,
    LegPostStateChirho,
};

const KIND_CHIRHO: &str = "money-kind-1-chirho";
const KIND_B_CHIRHO: &str = "money-kind-2-chirho";

fn account_chirho(owner_chirho: &str) -> AccountIdChirho {
    account_of_kind_chirho(owner_chirho, KIND_CHIRHO)
}

/// An account of an EXPLICIT stable kind. An account IS its `(owner, kind_id)` identity (R5b), so a
/// cross-kind party is built by giving it a different `kind_id` — the kind rides the account, never
/// the leg's `kind_policy_ref`.
fn account_of_kind_chirho(owner_chirho: &str, kind_id_chirho: &str) -> AccountIdChirho {
    AccountIdChirho::new_chirho(owner_chirho, kind_id_chirho)
}

fn kind_ref_chirho(id_chirho: &str) -> AssetKindRefChirho {
    AssetKindRefChirho(DigestChirho(id_chirho.into()))
}

fn post_of_chirho(state_chirho: AccountStateChirho) -> LegPostStateChirho {
    LegPostStateChirho {
        credits_total_chirho: state_chirho.credits_chirho,
        debits_total_chirho: state_chirho.debits_chirho,
        held_chirho: state_chirho.held_chirho,
    }
}

/// Build legs with CORRECT posts (folded from current state); the `&str` overrides each leg's
/// `kind_policy_ref` — the versioned policy REVISION the leg cites, NOT the conservation key (which
/// is the account's stable `kind_id`). Distinct refs on same-kind accounts still conserve as one kind.
fn legs_with_policy_refs_chirho(
    ledger_chirho: &RefLedgerChirho,
    specs_chirho: &[(AccountIdChirho, LegDeltaChirho, u64, &str)],
) -> Vec<LedgerLegChirho> {
    let mut scratch_chirho: std::collections::BTreeMap<AccountIdChirho, AccountStateChirho> =
        std::collections::BTreeMap::new();
    let mut legs_chirho = Vec::new();
    for (account_chirho, delta_chirho, amount_chirho, policy_ref_chirho) in specs_chirho {
        let current_chirho = scratch_chirho
            .get(account_chirho)
            .copied()
            .unwrap_or_else(|| ledger_chirho.state_chirho(account_chirho));
        let next_chirho = fold_leg_chirho(current_chirho, delta_chirho, *amount_chirho).unwrap();
        scratch_chirho.insert(account_chirho.clone(), next_chirho);
        legs_chirho.push(LedgerLegChirho {
            account_chirho: account_chirho.clone(),
            kind_policy_ref_chirho: kind_ref_chirho(policy_ref_chirho),
            delta_chirho: delta_chirho.clone(),
            amount_chirho: *amount_chirho,
            post_chirho: post_of_chirho(next_chirho),
            counterpart_chirho: None,
        });
    }
    legs_chirho
}

fn valid_legs_chirho(
    ledger_chirho: &RefLedgerChirho,
    specs_chirho: &[(AccountIdChirho, LegDeltaChirho, u64)],
) -> Vec<LedgerLegChirho> {
    let widened_chirho: Vec<_> = specs_chirho
        .iter()
        .map(|(a_chirho, d_chirho, amt_chirho)| {
            (a_chirho.clone(), d_chirho.clone(), *amt_chirho, KIND_CHIRHO)
        })
        .collect();
    legs_with_policy_refs_chirho(ledger_chirho, &widened_chirho)
}

/// A leg with a dummy post — for op->leg SHAPE / Unsupported rejects (grammar runs before post/fold).
fn raw_leg_chirho(
    owner_chirho: &str,
    delta_chirho: LegDeltaChirho,
    amount_chirho: u64,
) -> LedgerLegChirho {
    LedgerLegChirho {
        account_chirho: account_chirho(owner_chirho),
        kind_policy_ref_chirho: kind_ref_chirho(KIND_CHIRHO),
        delta_chirho,
        amount_chirho,
        post_chirho: LegPostStateChirho {
            credits_total_chirho: 0,
            debits_total_chirho: 0,
            held_chirho: 0,
        },
        counterpart_chirho: None,
    }
}

fn mint_op_chirho() -> LedgerOpChirho {
    LedgerOpChirho::MintChirho {
        authority_evidence_chirho: DigestChirho("mint-authority-chirho".into()),
    }
}

fn burn_op_chirho() -> LedgerOpChirho {
    LedgerOpChirho::BurnChirho {
        authority_evidence_chirho: DigestChirho("burn-authority-chirho".into()),
    }
}

fn escrow_control_chirho(step_chirho: u32) -> EscrowControlChirho {
    EscrowControlChirho {
        saga_id_chirho: DigestChirho("saga-fixture-chirho".into()),
        step_chirho,
    }
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
        amount_chirho: 10,
        kind_policy_ref_chirho: kind_ref_chirho(KIND_CHIRHO),
        src_chirho: account_chirho("src"),
        dst_money_group_chirho: dst_mg_chirho,
        dst_cluster_chirho: dst_cl_chirho,
        dst_chirho: dst_chirho.clone(),
        channel_chirho,
        nullifier_chirho,
    }
}

/// Apply a valid single-Credit Mint through the raw checker (admission is B's; here it is just the
/// arithmetic that lets later transfers have a funded source).
fn mint_chirho(
    ledger_chirho: &mut RefLedgerChirho,
    account_chirho: &AccountIdChirho,
    amount_chirho: u64,
) {
    let legs_chirho = valid_legs_chirho(
        ledger_chirho,
        &[(
            account_chirho.clone(),
            LegDeltaChirho::CreditChirho,
            amount_chirho,
        )],
    );
    ledger_chirho
        .apply_grammar_arithmetic_chirho(&legs_chirho, &mint_op_chirho())
        .expect("mint applies");
}

// ---- arithmetic happy paths (per-account, no misleading unitless total) ---------------------------

#[test]
fn internal_transfer_conserves_and_moves_money_chirho() {
    let mut ledger_chirho = RefLedgerChirho::new_chirho();
    let a_chirho = account_chirho("alice");
    let b_chirho = account_chirho("bob");
    mint_chirho(&mut ledger_chirho, &a_chirho, 100);

    let legs_chirho = valid_legs_chirho(
        &ledger_chirho,
        &[
            (a_chirho.clone(), LegDeltaChirho::DebitChirho, 40),
            (b_chirho.clone(), LegDeltaChirho::CreditChirho, 40),
        ],
    );
    ledger_chirho
        .apply_grammar_arithmetic_chirho(&legs_chirho, &LedgerOpChirho::TransferChirho)
        .expect("transfer applies");

    // A single-kind transfer moves money but creates none: A + B still sum to the minted 100.
    assert_eq!(ledger_chirho.state_chirho(&a_chirho).net_money_chirho(), 60);
    assert_eq!(ledger_chirho.state_chirho(&b_chirho).net_money_chirho(), 40);
}

#[test]
fn overdraft_is_refused_no_double_spend_chirho() {
    let mut ledger_chirho = RefLedgerChirho::new_chirho();
    let a_chirho = account_chirho("alice");
    let b_chirho = account_chirho("bob");
    mint_chirho(&mut ledger_chirho, &a_chirho, 100);

    let spend1_chirho = valid_legs_chirho(
        &ledger_chirho,
        &[
            (a_chirho.clone(), LegDeltaChirho::DebitChirho, 100),
            (b_chirho.clone(), LegDeltaChirho::CreditChirho, 100),
        ],
    );
    ledger_chirho
        .apply_grammar_arithmetic_chirho(&spend1_chirho, &LedgerOpChirho::TransferChirho)
        .expect("first spend ok");

    let spend2_chirho = valid_legs_chirho(
        &ledger_chirho,
        &[
            (a_chirho.clone(), LegDeltaChirho::DebitChirho, 100),
            (b_chirho.clone(), LegDeltaChirho::CreditChirho, 100),
        ],
    );
    assert_eq!(
        ledger_chirho
            .apply_grammar_arithmetic_chirho(&spend2_chirho, &LedgerOpChirho::TransferChirho),
        Err(RejectReasonChirho::OverdraftChirho)
    );
    assert_eq!(
        ledger_chirho.state_chirho(&b_chirho).net_money_chirho(),
        100
    );
}

#[test]
fn forged_post_is_refused_chirho() {
    let mut ledger_chirho = RefLedgerChirho::new_chirho();
    let a_chirho = account_chirho("alice");
    let b_chirho = account_chirho("bob");
    mint_chirho(&mut ledger_chirho, &a_chirho, 100);

    let mut forged_chirho = valid_legs_chirho(
        &ledger_chirho,
        &[
            (a_chirho.clone(), LegDeltaChirho::DebitChirho, 40),
            (b_chirho.clone(), LegDeltaChirho::CreditChirho, 40),
        ],
    );
    forged_chirho[1].post_chirho.credits_total_chirho = 999;
    assert_eq!(
        ledger_chirho
            .apply_grammar_arithmetic_chirho(&forged_chirho, &LedgerOpChirho::TransferChirho),
        Err(RejectReasonChirho::PostMismatchChirho)
    );
}

#[test]
fn same_kind_unbalanced_transfer_is_refused_chirho() {
    let mut ledger_chirho = RefLedgerChirho::new_chirho();
    let a_chirho = account_chirho("alice");
    let b_chirho = account_chirho("bob");
    mint_chirho(&mut ledger_chirho, &a_chirho, 100);

    let unbalanced_chirho = valid_legs_chirho(
        &ledger_chirho,
        &[
            (a_chirho.clone(), LegDeltaChirho::DebitChirho, 40),
            (b_chirho.clone(), LegDeltaChirho::CreditChirho, 30),
        ],
    );
    assert_eq!(
        ledger_chirho
            .apply_grammar_arithmetic_chirho(&unbalanced_chirho, &LedgerOpChirho::TransferChirho),
        Err(RejectReasonChirho::NotBalancedChirho)
    );
}

#[test]
fn mint_creates_money_burn_destroys_it_chirho() {
    let mut ledger_chirho = RefLedgerChirho::new_chirho();
    let a_chirho = account_chirho("alice");
    mint_chirho(&mut ledger_chirho, &a_chirho, 100);
    assert_eq!(
        ledger_chirho.state_chirho(&a_chirho).net_money_chirho(),
        100
    );

    let burn_legs_chirho = valid_legs_chirho(
        &ledger_chirho,
        &[(a_chirho.clone(), LegDeltaChirho::DebitChirho, 30)],
    );
    ledger_chirho
        .apply_grammar_arithmetic_chirho(&burn_legs_chirho, &burn_op_chirho())
        .expect("burn applies");
    assert_eq!(ledger_chirho.state_chirho(&a_chirho).net_money_chirho(), 70);
}

#[test]
fn cross_kind_transfer_is_refused_per_kind_chirho() {
    // Debit 40 from a kind-A account + Credit 40 to a DIFFERENT-kind (kind-B) account: the TOTAL nets
    // zero, but per-kind A:-40 / B:+40 mints B and burns A. Conservation keys by the account's STABLE
    // `kind_id` (R5b) — the kind rides the account, not the leg's policy ref — so a unitless sum would
    // (wrongly) accept while per-kind MUST refuse.
    let mut ledger_chirho = RefLedgerChirho::new_chirho();
    let a_chirho = account_chirho("alice");
    let b_chirho = account_of_kind_chirho("bob", KIND_B_CHIRHO);
    mint_chirho(&mut ledger_chirho, &a_chirho, 100);

    let cross_chirho = legs_with_policy_refs_chirho(
        &ledger_chirho,
        &[
            (
                a_chirho.clone(),
                LegDeltaChirho::DebitChirho,
                40,
                KIND_CHIRHO,
            ),
            (
                b_chirho.clone(),
                LegDeltaChirho::CreditChirho,
                40,
                KIND_B_CHIRHO,
            ),
        ],
    );
    assert_eq!(
        ledger_chirho
            .apply_grammar_arithmetic_chirho(&cross_chirho, &LedgerOpChirho::TransferChirho),
        Err(RejectReasonChirho::NotBalancedChirho)
    );
}

#[test]
fn mixed_policy_refs_same_kind_still_conserve_chirho() {
    // The A1 re-key pin (companion to admission RK.*): two accounts of the SAME stable kind, but the
    // debit and credit legs cite DIFFERENT policy REVISIONS (v1, v2) — as if the kind's policy was
    // revised between the accounts' admissions. Conservation keys by the account's STABLE `kind_id`
    // (R5b), so both legs land on ONE kind and the transfer BALANCES. Keying by the versioned
    // `kind_policy_ref` (the pre-R5b defect) would see two kinds, each nonzero, and FALSELY refuse a
    // balanced same-kind transfer — stranding money on a policy revision, the exact failure the
    // two-concept identity forbids. (Whether a ref actually resolves to the account's kind needs the
    // registry, so wrong-kind / unregistered-ref are admission REDs — RK.* — not reference tests.)
    let mut ledger_chirho = RefLedgerChirho::new_chirho();
    let a_chirho = account_chirho("alice");
    let b_chirho = account_chirho("bob");
    mint_chirho(&mut ledger_chirho, &a_chirho, 100);

    let legs_chirho = legs_with_policy_refs_chirho(
        &ledger_chirho,
        &[
            (
                a_chirho.clone(),
                LegDeltaChirho::DebitChirho,
                40,
                "money-kind-policy-v1-chirho",
            ),
            (
                b_chirho.clone(),
                LegDeltaChirho::CreditChirho,
                40,
                "money-kind-policy-v2-chirho",
            ),
        ],
    );
    ledger_chirho
        .apply_grammar_arithmetic_chirho(&legs_chirho, &LedgerOpChirho::TransferChirho)
        .expect(
            "same-kind transfer under different policy revisions must conserve, not strand money",
        );
    assert_eq!(ledger_chirho.state_chirho(&a_chirho).net_money_chirho(), 60);
    assert_eq!(ledger_chirho.state_chirho(&b_chirho).net_money_chirho(), 40);
}

#[test]
fn timer_with_zero_money_legs_is_supported_chirho() {
    let mut ledger_chirho = RefLedgerChirho::new_chirho();
    let timer_op_chirho = LedgerOpChirho::TimerChirho {
        fires_at_hlc_chirho: HlcChirho {
            physical_ms_chirho: 42,
            logical_chirho: 0,
        },
        purpose_chirho: "sweep-chirho".into(),
    };
    assert_eq!(
        ledger_chirho.apply_grammar_arithmetic_chirho(&[], &timer_op_chirho),
        Ok(Vec::new())
    );
}

// ---- op->leg grammar-SHAPE counterexamples: every one REFUSED ------------------------------------

#[test]
fn mint_with_a_debit_leg_is_refused_chirho() {
    let mut ledger_chirho = RefLedgerChirho::new_chirho();
    assert_eq!(
        ledger_chirho.apply_grammar_arithmetic_chirho(
            &[raw_leg_chirho("a", LegDeltaChirho::DebitChirho, 30)],
            &mint_op_chirho()
        ),
        Err(RejectReasonChirho::BadOperationShapeChirho)
    );
}

#[test]
fn burn_with_a_credit_leg_is_refused_chirho() {
    let mut ledger_chirho = RefLedgerChirho::new_chirho();
    assert_eq!(
        ledger_chirho.apply_grammar_arithmetic_chirho(
            &[raw_leg_chirho("a", LegDeltaChirho::CreditChirho, 30)],
            &burn_op_chirho()
        ),
        Err(RejectReasonChirho::BadOperationShapeChirho)
    );
}

#[test]
fn empty_and_lone_hold_transfers_are_refused_chirho() {
    let mut ledger_chirho = RefLedgerChirho::new_chirho();
    assert_eq!(
        ledger_chirho.apply_grammar_arithmetic_chirho(&[], &LedgerOpChirho::TransferChirho),
        Err(RejectReasonChirho::BadOperationShapeChirho)
    );
    let hold_legs_chirho = vec![
        raw_leg_chirho("a", LegDeltaChirho::DebitChirho, 40),
        raw_leg_chirho("b", LegDeltaChirho::HoldChirho, 40),
    ];
    assert_eq!(
        ledger_chirho
            .apply_grammar_arithmetic_chirho(&hold_legs_chirho, &LedgerOpChirho::TransferChirho),
        Err(RejectReasonChirho::BadOperationShapeChirho)
    );
}

#[test]
fn canonical_escrow_lifecycle_preserves_money_chirho() {
    let mut ledger_chirho = RefLedgerChirho::new_chirho();
    let payer_chirho = account_chirho("payer");
    let settlement_chirho = account_chirho("settlement");
    mint_chirho(&mut ledger_chirho, &payer_chirho, 100);

    let hold_legs_chirho = valid_legs_chirho(
        &ledger_chirho,
        &[(payer_chirho.clone(), LegDeltaChirho::HoldChirho, 40)],
    );
    ledger_chirho
        .apply_grammar_arithmetic_chirho(
            &hold_legs_chirho,
            &LedgerOpChirho::EscrowHoldChirho {
                control_chirho: escrow_control_chirho(1),
            },
        )
        .expect("canonical escrow hold must apply");
    assert_eq!(ledger_chirho.state_chirho(&payer_chirho).held_chirho, 40);
    assert_eq!(
        ledger_chirho.state_chirho(&payer_chirho).net_money_chirho(),
        100
    );

    let release_legs_chirho = valid_legs_chirho(
        &ledger_chirho,
        &[(payer_chirho.clone(), LegDeltaChirho::ReleaseChirho, 40)],
    );
    ledger_chirho
        .apply_grammar_arithmetic_chirho(
            &release_legs_chirho,
            &LedgerOpChirho::EscrowReleaseChirho {
                control_chirho: escrow_control_chirho(1),
            },
        )
        .expect("canonical escrow release must apply");
    assert_eq!(ledger_chirho.state_chirho(&payer_chirho).held_chirho, 0);
    assert_eq!(
        ledger_chirho.state_chirho(&payer_chirho).net_money_chirho(),
        100
    );

    let second_hold_legs_chirho = valid_legs_chirho(
        &ledger_chirho,
        &[(payer_chirho.clone(), LegDeltaChirho::HoldChirho, 40)],
    );
    ledger_chirho
        .apply_grammar_arithmetic_chirho(
            &second_hold_legs_chirho,
            &LedgerOpChirho::EscrowHoldChirho {
                control_chirho: escrow_control_chirho(2),
            },
        )
        .expect("second escrow step hold must apply");

    let finalize_legs_chirho = valid_legs_chirho(
        &ledger_chirho,
        &[
            (payer_chirho.clone(), LegDeltaChirho::FinalizeChirho, 40),
            (settlement_chirho.clone(), LegDeltaChirho::CreditChirho, 40),
        ],
    );
    ledger_chirho
        .apply_grammar_arithmetic_chirho(
            &finalize_legs_chirho,
            &LedgerOpChirho::EscrowFinalizeChirho {
                control_chirho: escrow_control_chirho(2),
            },
        )
        .expect("canonical escrow finalize must apply");

    assert_eq!(ledger_chirho.state_chirho(&payer_chirho).held_chirho, 0);
    assert_eq!(
        ledger_chirho.state_chirho(&payer_chirho).net_money_chirho(),
        60
    );
    assert_eq!(
        ledger_chirho
            .state_chirho(&settlement_chirho)
            .net_money_chirho(),
        40
    );
}

#[test]
fn malformed_escrow_shapes_are_refused_chirho() {
    let mut ledger_chirho = RefLedgerChirho::new_chirho();
    let mut counterpart_hold_chirho = raw_leg_chirho("a", LegDeltaChirho::HoldChirho, 50);
    let counterpart_dst_chirho = counterpart_hold_chirho.account_chirho.clone();
    counterpart_hold_chirho.counterpart_chirho =
        Some(dummy_counterpart_chirho(&counterpart_dst_chirho));
    let mut counterpart_release_chirho = raw_leg_chirho("a", LegDeltaChirho::ReleaseChirho, 50);
    counterpart_release_chirho.counterpart_chirho =
        Some(dummy_counterpart_chirho(&counterpart_dst_chirho));
    let finalize_leg_chirho = raw_leg_chirho("a", LegDeltaChirho::FinalizeChirho, 50);
    let mut counterpart_credit_chirho =
        raw_leg_chirho("settlement", LegDeltaChirho::CreditChirho, 50);
    let counterpart_credit_dst_chirho = counterpart_credit_chirho.account_chirho.clone();
    counterpart_credit_chirho.counterpart_chirho =
        Some(dummy_counterpart_chirho(&counterpart_credit_dst_chirho));
    let cases_chirho: Vec<(Vec<LedgerLegChirho>, LedgerOpChirho)> = vec![
        (
            Vec::new(),
            LedgerOpChirho::EscrowHoldChirho {
                control_chirho: escrow_control_chirho(1),
            },
        ),
        (
            vec![raw_leg_chirho("a", LegDeltaChirho::ReleaseChirho, 50)],
            LedgerOpChirho::EscrowHoldChirho {
                control_chirho: escrow_control_chirho(1),
            },
        ),
        (
            vec![
                raw_leg_chirho("a", LegDeltaChirho::HoldChirho, 25),
                raw_leg_chirho("a", LegDeltaChirho::HoldChirho, 25),
            ],
            LedgerOpChirho::EscrowHoldChirho {
                control_chirho: escrow_control_chirho(1),
            },
        ),
        (
            vec![counterpart_hold_chirho],
            LedgerOpChirho::EscrowHoldChirho {
                control_chirho: escrow_control_chirho(1),
            },
        ),
        (
            vec![raw_leg_chirho("a", LegDeltaChirho::HoldChirho, 50)],
            LedgerOpChirho::EscrowReleaseChirho {
                control_chirho: escrow_control_chirho(1),
            },
        ),
        (
            vec![counterpart_release_chirho],
            LedgerOpChirho::EscrowReleaseChirho {
                control_chirho: escrow_control_chirho(1),
            },
        ),
        (
            vec![
                raw_leg_chirho("a", LegDeltaChirho::ReleaseChirho, 25),
                raw_leg_chirho("a", LegDeltaChirho::ReleaseChirho, 25),
            ],
            LedgerOpChirho::EscrowReleaseChirho {
                control_chirho: escrow_control_chirho(1),
            },
        ),
        (
            vec![raw_leg_chirho("a", LegDeltaChirho::FinalizeChirho, 50)],
            LedgerOpChirho::EscrowFinalizeChirho {
                control_chirho: escrow_control_chirho(1),
            },
        ),
        (
            vec![
                raw_leg_chirho("settlement", LegDeltaChirho::CreditChirho, 50),
                raw_leg_chirho("a", LegDeltaChirho::FinalizeChirho, 50),
            ],
            LedgerOpChirho::EscrowFinalizeChirho {
                control_chirho: escrow_control_chirho(1),
            },
        ),
        (
            vec![
                raw_leg_chirho("a", LegDeltaChirho::FinalizeChirho, 50),
                raw_leg_chirho("settlement", LegDeltaChirho::DebitChirho, 50),
            ],
            LedgerOpChirho::EscrowFinalizeChirho {
                control_chirho: escrow_control_chirho(1),
            },
        ),
        (
            vec![finalize_leg_chirho, counterpart_credit_chirho],
            LedgerOpChirho::EscrowFinalizeChirho {
                control_chirho: escrow_control_chirho(1),
            },
        ),
        (
            vec![
                raw_leg_chirho("a", LegDeltaChirho::FinalizeChirho, 50),
                raw_leg_chirho("settlement", LegDeltaChirho::CreditChirho, 50),
                raw_leg_chirho("extra", LegDeltaChirho::CreditChirho, 1),
            ],
            LedgerOpChirho::EscrowFinalizeChirho {
                control_chirho: escrow_control_chirho(1),
            },
        ),
    ];
    for (legs_chirho, op_chirho) in cases_chirho {
        assert_eq!(
            ledger_chirho.apply_grammar_arithmetic_chirho(&legs_chirho, &op_chirho),
            Err(RejectReasonChirho::BadOperationShapeChirho),
            "malformed shape of {op_chirho:?} must be refused"
        );
    }
}

#[test]
fn escrow_finalize_requires_equal_amount_and_kind_chirho() {
    let mut ledger_chirho = RefLedgerChirho::new_chirho();
    let payer_chirho = account_chirho("payer");
    let settlement_chirho = account_chirho("settlement");
    let other_kind_settlement_chirho = account_of_kind_chirho("settlement-b", KIND_B_CHIRHO);
    mint_chirho(&mut ledger_chirho, &payer_chirho, 100);
    let hold_legs_chirho = valid_legs_chirho(
        &ledger_chirho,
        &[(payer_chirho.clone(), LegDeltaChirho::HoldChirho, 50)],
    );
    ledger_chirho
        .apply_grammar_arithmetic_chirho(
            &hold_legs_chirho,
            &LedgerOpChirho::EscrowHoldChirho {
                control_chirho: escrow_control_chirho(1),
            },
        )
        .expect("escrow hold must establish the finalize pre-state");

    let amount_skew_chirho = valid_legs_chirho(
        &ledger_chirho,
        &[
            (payer_chirho.clone(), LegDeltaChirho::FinalizeChirho, 50),
            (settlement_chirho.clone(), LegDeltaChirho::CreditChirho, 49),
        ],
    );
    assert_eq!(
        ledger_chirho.apply_grammar_arithmetic_chirho(
            &amount_skew_chirho,
            &LedgerOpChirho::EscrowFinalizeChirho {
                control_chirho: escrow_control_chirho(1),
            },
        ),
        Err(RejectReasonChirho::NotBalancedChirho)
    );

    let kind_skew_chirho = legs_with_policy_refs_chirho(
        &ledger_chirho,
        &[
            (
                payer_chirho.clone(),
                LegDeltaChirho::FinalizeChirho,
                50,
                KIND_CHIRHO,
            ),
            (
                other_kind_settlement_chirho,
                LegDeltaChirho::CreditChirho,
                50,
                KIND_B_CHIRHO,
            ),
        ],
    );
    assert_eq!(
        ledger_chirho.apply_grammar_arithmetic_chirho(
            &kind_skew_chirho,
            &LedgerOpChirho::EscrowFinalizeChirho {
                control_chirho: escrow_control_chirho(1),
            },
        ),
        Err(RejectReasonChirho::NotBalancedChirho)
    );
}

#[test]
fn nonempty_timer_and_bare_credit_debit_and_compensation_are_refused_chirho() {
    let mut ledger_chirho = RefLedgerChirho::new_chirho();
    // A Timer carrying money legs is a shape violation (Timer is exactly zero legs).
    let timer_op_chirho = LedgerOpChirho::TimerChirho {
        fires_at_hlc_chirho: HlcChirho {
            physical_ms_chirho: 0,
            logical_chirho: 0,
        },
        purpose_chirho: String::new(),
    };
    assert_eq!(
        ledger_chirho.apply_grammar_arithmetic_chirho(
            &[raw_leg_chirho("a", LegDeltaChirho::CreditChirho, 10)],
            &timer_op_chirho
        ),
        Err(RejectReasonChirho::BadOperationShapeChirho)
    );
    // Bare Credit / Debit / Compensation are ExplicitlyUnsupported.
    assert_eq!(
        ledger_chirho.apply_grammar_arithmetic_chirho(
            &[raw_leg_chirho("a", LegDeltaChirho::CreditChirho, 30)],
            &LedgerOpChirho::CreditChirho
        ),
        Err(RejectReasonChirho::UnsupportedOperationChirho)
    );
    assert_eq!(
        ledger_chirho.apply_grammar_arithmetic_chirho(
            &[raw_leg_chirho("a", LegDeltaChirho::DebitChirho, 30)],
            &LedgerOpChirho::DebitChirho
        ),
        Err(RejectReasonChirho::UnsupportedOperationChirho)
    );
    assert_eq!(
        ledger_chirho.apply_grammar_arithmetic_chirho(
            &[raw_leg_chirho("a", LegDeltaChirho::CreditChirho, 30)],
            &LedgerOpChirho::CompensationChirho {
                of_chirho: DigestChirho("x-chirho".into())
            }
        ),
        Err(RejectReasonChirho::UnsupportedOperationChirho)
    );
}

#[test]
fn counterpart_transfer_shape_admits_through_the_arithmetic_oracle_chirho() {
    // The oracle owns only the amended table's ordered shape + NetZero law. Finality, nullifier, and
    // settlement-role authority remain B-only and therefore are deliberately not inferred here.
    let mut ledger_chirho = RefLedgerChirho::new_chirho();
    let a_chirho = account_chirho("alice");
    let b_chirho = account_chirho("bob");
    mint_chirho(&mut ledger_chirho, &a_chirho, 40);
    let mut legs_chirho = valid_legs_chirho(
        &ledger_chirho,
        &[
            (a_chirho.clone(), LegDeltaChirho::DebitChirho, 40),
            (b_chirho.clone(), LegDeltaChirho::CreditChirho, 40),
        ],
    );
    let mut claim_chirho = dummy_counterpart_chirho(&b_chirho);
    claim_chirho.amount_chirho = 40;
    legs_chirho[1].counterpart_chirho = Some(claim_chirho);

    assert_eq!(
        ledger_chirho
            .apply_grammar_arithmetic_chirho(&legs_chirho, &LedgerOpChirho::TransferChirho),
        Ok(vec![
            post_of_chirho(AccountStateChirho {
                credits_chirho: 40,
                debits_chirho: 40,
                held_chirho: 0,
            }),
            post_of_chirho(AccountStateChirho {
                credits_chirho: 40,
                debits_chirho: 0,
                held_chirho: 0,
            })
        ])
    );
}

#[test]
fn counterpart_transfer_requires_exact_order_and_credit_only_claim_chirho() {
    let mut ledger_chirho = RefLedgerChirho::new_chirho();
    let dst_chirho = account_chirho("bob");
    let claim_chirho = dummy_counterpart_chirho(&dst_chirho);

    let mut claim_on_debit_chirho = raw_leg_chirho("alice", LegDeltaChirho::DebitChirho, 40);
    claim_on_debit_chirho.counterpart_chirho = Some(claim_chirho.clone());
    let credit_chirho = raw_leg_chirho("bob", LegDeltaChirho::CreditChirho, 40);
    assert_eq!(
        ledger_chirho.apply_grammar_arithmetic_chirho(
            &[claim_on_debit_chirho, credit_chirho.clone()],
            &LedgerOpChirho::TransferChirho,
        ),
        Err(RejectReasonChirho::BadOperationShapeChirho)
    );

    let debit_chirho = raw_leg_chirho("alice", LegDeltaChirho::DebitChirho, 40);
    let mut claim_on_credit_chirho = credit_chirho;
    claim_on_credit_chirho.counterpart_chirho = Some(claim_chirho);
    let mut claim_on_both_debit_chirho = debit_chirho.clone();
    claim_on_both_debit_chirho.counterpart_chirho = Some(dummy_counterpart_chirho(&dst_chirho));
    assert_eq!(
        ledger_chirho.apply_grammar_arithmetic_chirho(
            &[claim_on_both_debit_chirho, claim_on_credit_chirho.clone()],
            &LedgerOpChirho::TransferChirho,
        ),
        Err(RejectReasonChirho::BadOperationShapeChirho)
    );
    assert_eq!(
        ledger_chirho.apply_grammar_arithmetic_chirho(
            &[claim_on_credit_chirho.clone(), debit_chirho.clone()],
            &LedgerOpChirho::TransferChirho,
        ),
        Err(RejectReasonChirho::BadOperationShapeChirho)
    );
    assert_eq!(
        ledger_chirho.apply_grammar_arithmetic_chirho(
            &[
                debit_chirho.clone(),
                claim_on_credit_chirho.clone(),
                debit_chirho
            ],
            &LedgerOpChirho::TransferChirho,
        ),
        Err(RejectReasonChirho::BadOperationShapeChirho)
    );
}

// ---- overflow / multi-party / conservation-sweep hardening (live CF1 paths) -----------------------

#[test]
fn credit_overflow_is_arithmetic_reject_not_wrap_chirho() {
    // Fund an account near the u64 ceiling, then a further credit that would overflow the counter must
    // be REFUSED (§11.3 checked-arith), NEVER silently wrapped to a tiny balance — a wrap manufactures
    // money. The fold fails before any post check, so the reject is Arithmetic.
    let mut ledger_chirho = RefLedgerChirho::new_chirho();
    let a_chirho = account_chirho("whale");
    mint_chirho(&mut ledger_chirho, &a_chirho, u64::MAX - 5);
    assert_eq!(
        ledger_chirho.apply_grammar_arithmetic_chirho(
            &[raw_leg_chirho("whale", LegDeltaChirho::CreditChirho, 10)],
            &mint_op_chirho()
        ),
        Err(RejectReasonChirho::ArithmeticChirho)
    );
    // Nothing partial/wrapped applied: the near-ceiling balance is unchanged.
    assert_eq!(
        ledger_chirho.state_chirho(&a_chirho).net_money_chirho(),
        (u64::MAX - 5) as i128
    );
}

#[test]
fn three_party_transfer_conserves_per_kind_chirho() {
    // Debit 100 from A, split as Credit 60 to B + Credit 40 to C: Σ per kind = 0, so it conserves and
    // moves money across THREE legs (the grammar allows >= 2 Credit/Debit legs, not just 2).
    let mut ledger_chirho = RefLedgerChirho::new_chirho();
    let a_chirho = account_chirho("alice");
    let b_chirho = account_chirho("bob");
    let c_chirho = account_chirho("carol");
    mint_chirho(&mut ledger_chirho, &a_chirho, 100);
    let legs_chirho = valid_legs_chirho(
        &ledger_chirho,
        &[
            (a_chirho.clone(), LegDeltaChirho::DebitChirho, 100),
            (b_chirho.clone(), LegDeltaChirho::CreditChirho, 60),
            (c_chirho.clone(), LegDeltaChirho::CreditChirho, 40),
        ],
    );
    ledger_chirho
        .apply_grammar_arithmetic_chirho(&legs_chirho, &LedgerOpChirho::TransferChirho)
        .expect("3-party transfer applies");
    assert_eq!(ledger_chirho.state_chirho(&a_chirho).net_money_chirho(), 0);
    assert_eq!(ledger_chirho.state_chirho(&b_chirho).net_money_chirho(), 60);
    assert_eq!(ledger_chirho.state_chirho(&c_chirho).net_money_chirho(), 40);
}

#[test]
fn three_party_unbalanced_transfer_is_refused_atomically_chirho() {
    // Debit 100 / Credit 60 / Credit 30 -> Σ = -10 for the kind (destroys 10) -> REFUSE, and no leg
    // applies (the balance check runs before commit): the source keeps its full 100.
    let mut ledger_chirho = RefLedgerChirho::new_chirho();
    let a_chirho = account_chirho("alice");
    let b_chirho = account_chirho("bob");
    let c_chirho = account_chirho("carol");
    mint_chirho(&mut ledger_chirho, &a_chirho, 100);
    let legs_chirho = valid_legs_chirho(
        &ledger_chirho,
        &[
            (a_chirho.clone(), LegDeltaChirho::DebitChirho, 100),
            (b_chirho.clone(), LegDeltaChirho::CreditChirho, 60),
            (c_chirho.clone(), LegDeltaChirho::CreditChirho, 30),
        ],
    );
    assert_eq!(
        ledger_chirho
            .apply_grammar_arithmetic_chirho(&legs_chirho, &LedgerOpChirho::TransferChirho),
        Err(RejectReasonChirho::NotBalancedChirho)
    );
    assert_eq!(
        ledger_chirho.state_chirho(&a_chirho).net_money_chirho(),
        100
    );
    assert_eq!(ledger_chirho.state_chirho(&b_chirho).net_money_chirho(), 0);
    assert_eq!(ledger_chirho.state_chirho(&c_chirho).net_money_chirho(), 0);
}

#[test]
fn conservation_sweep_across_splits_holds_total_chirho() {
    // A minted 1000 transferred at many split points always conserves: A + B == 1000 for EVERY split,
    // including the boundaries (0, full, and either side of the midpoint). A deterministic sweep so no
    // single hand-picked amount can hide a boundary bug.
    for split_chirho in [0u64, 1, 250, 499, 500, 501, 999, 1000] {
        let mut ledger_chirho = RefLedgerChirho::new_chirho();
        let a_chirho = account_chirho("alice");
        let b_chirho = account_chirho("bob");
        mint_chirho(&mut ledger_chirho, &a_chirho, 1000);
        if split_chirho > 0 {
            let legs_chirho = valid_legs_chirho(
                &ledger_chirho,
                &[
                    (a_chirho.clone(), LegDeltaChirho::DebitChirho, split_chirho),
                    (b_chirho.clone(), LegDeltaChirho::CreditChirho, split_chirho),
                ],
            );
            ledger_chirho
                .apply_grammar_arithmetic_chirho(&legs_chirho, &LedgerOpChirho::TransferChirho)
                .expect("transfer applies");
        }
        let total_chirho = ledger_chirho.state_chirho(&a_chirho).net_money_chirho()
            + ledger_chirho.state_chirho(&b_chirho).net_money_chirho();
        assert_eq!(
            total_chirho, 1000,
            "split {split_chirho} broke conservation"
        );
        assert_eq!(
            ledger_chirho.state_chirho(&b_chirho).net_money_chirho(),
            split_chirho as i128
        );
    }
}

#[test]
fn large_value_transfer_is_exact_no_precision_loss_chirho() {
    // Near-u64 amounts transfer EXACTLY: the fold is integer/checked and net_money is i128, so there is
    // no float rounding. A precision bug would show as an off-by-delta on B.
    let big_chirho = u64::MAX - 1000;
    let mut ledger_chirho = RefLedgerChirho::new_chirho();
    let a_chirho = account_chirho("alice");
    let b_chirho = account_chirho("bob");
    mint_chirho(&mut ledger_chirho, &a_chirho, big_chirho);
    let legs_chirho = valid_legs_chirho(
        &ledger_chirho,
        &[
            (a_chirho.clone(), LegDeltaChirho::DebitChirho, big_chirho),
            (b_chirho.clone(), LegDeltaChirho::CreditChirho, big_chirho),
        ],
    );
    ledger_chirho
        .apply_grammar_arithmetic_chirho(&legs_chirho, &LedgerOpChirho::TransferChirho)
        .expect("large transfer applies");
    assert_eq!(ledger_chirho.state_chirho(&a_chirho).net_money_chirho(), 0);
    assert_eq!(
        ledger_chirho.state_chirho(&b_chirho).net_money_chirho(),
        big_chirho as i128
    );
}
