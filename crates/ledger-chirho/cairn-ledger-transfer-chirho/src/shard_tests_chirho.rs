// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Hot-account shard proofs (C1-C3, #5030/#5033): declaration-chain law, the hostile look-alike
//! invisibility RED, round-robin fan-out with the STRUCTURAL chain-depth bench (same-journal
//! regime, honestly framed), router-discipline debit serialization, ordinary-Transfer
//! consolidation, and the explicit F3 gate on the cross-journal regime.

use crate::coordinator_tests_chirho::{
    FakeJournalSignerChirho, JournalFixtureChirho, MemoryStorageChirho, SharedClockChirho,
};
use crate::shard_chirho::{
    append_shard_set_op_chirho, canonical_shard_set_line_chirho, load_shard_sets_chirho,
    logical_net_chirho, parse_canonical_shard_set_line_chirho, route_credit_shard_chirho,
    ShardSetOpChirho, ShardSetRecordChirho, SHARD_SET_SCHEMA_V1_CHIRHO,
};
use cairn_ledger_log_chirho::journal_chirho::LedgerJournalChirho;
use cairn_ledger_log_chirho::ports_chirho::{
    LedgerSignerPortChirho, LedgerStoragePortChirho, StoragePathChirho,
};
use cairn_ledger_model_chirho::counterpart_chirho::{
    CounterpartClaimChirho, CounterpartNullifierChirho, FinalBurnRefChirho,
};
use cairn_ledger_model_chirho::ids_chirho::{
    AssetKindRefChirho, ClusterIdChirho, DigestChirho, MoneyGroupIdChirho,
    SettlementChannelIdChirho, TransferIdChirho,
};
use cairn_ledger_model_chirho::LogIdChirho;
use std::cell::Cell;
use std::collections::BTreeMap;

/// The parent-owner root for declaration signing — a scheme distinct from the journal's.
struct OwnerRootSignerChirho;

impl LedgerSignerPortChirho for OwnerRootSignerChirho {
    fn sign_chirho(&self, signed_content_line_chirho: &str) -> anyhow::Result<String> {
        Ok(format!(
            "owner-sig-{}",
            &blake3::hash(signed_content_line_chirho.as_bytes()).to_hex()[..16]
        ))
    }

    fn key_id_chirho(&self) -> String {
        "owner-root-key-chirho".to_owned()
    }

    fn verify_chirho(&self, signed_content_line_chirho: &str, sig_chirho: &str) -> bool {
        self.sign_chirho(signed_content_line_chirho)
            .map(|expected_chirho| expected_chirho == sig_chirho)
            .unwrap_or(false)
    }
}

const SHARD_LOG_ID_CHIRHO: &str = "shard-sets-alpha-chirho";

fn shard_path_chirho() -> StoragePathChirho {
    StoragePathChirho("shards/alpha.jsonl".into())
}

fn declared_shards_chirho() -> Vec<String> {
    vec![
        "merchant-shard-0-chirho".to_owned(),
        "merchant-shard-1-chirho".to_owned(),
        "merchant-shard-2-chirho".to_owned(),
    ]
}

#[test]
fn declaration_chain_lifecycle_and_refusals_chirho() {
    let storage_chirho = MemoryStorageChirho::default();
    let owner_chirho = OwnerRootSignerChirho;
    append_shard_set_op_chirho(
        &storage_chirho,
        &owner_chirho,
        &shard_path_chirho(),
        SHARD_LOG_ID_CHIRHO,
        "merchant-chirho",
        "money-chirho",
        ShardSetOpChirho::DeclareChirho {
            shards_chirho: declared_shards_chirho(),
        },
    )
    .unwrap();
    // First declaration wins.
    assert!(append_shard_set_op_chirho(
        &storage_chirho,
        &owner_chirho,
        &shard_path_chirho(),
        SHARD_LOG_ID_CHIRHO,
        "merchant-chirho",
        "money-chirho",
        ShardSetOpChirho::DeclareChirho {
            shards_chirho: vec!["other-chirho".to_owned()],
        },
    )
    .is_err());
    // Amend of an undeclared key refuses; amend of the declared key replaces.
    assert!(append_shard_set_op_chirho(
        &storage_chirho,
        &owner_chirho,
        &shard_path_chirho(),
        SHARD_LOG_ID_CHIRHO,
        "nobody-chirho",
        "money-chirho",
        ShardSetOpChirho::AmendChirho {
            shards_chirho: vec!["x-chirho".to_owned()],
        },
    )
    .is_err());
    append_shard_set_op_chirho(
        &storage_chirho,
        &owner_chirho,
        &shard_path_chirho(),
        SHARD_LOG_ID_CHIRHO,
        "merchant-chirho",
        "money-chirho",
        ShardSetOpChirho::AmendChirho {
            shards_chirho: vec![
                "merchant-shard-0-chirho".to_owned(),
                "merchant-shard-1-chirho".to_owned(),
            ],
        },
    )
    .unwrap();
    let loaded_chirho = load_shard_sets_chirho(
        &storage_chirho,
        &owner_chirho,
        &shard_path_chirho(),
        SHARD_LOG_ID_CHIRHO,
    )
    .unwrap();
    assert_eq!(
        loaded_chirho.shards_chirho("merchant-chirho", "money-chirho"),
        Some(
            &[
                "merchant-shard-0-chirho".to_owned(),
                "merchant-shard-1-chirho".to_owned()
            ][..]
        )
    );
    // Canonical-set refusals: unsorted, duplicate, self-shard, empty.
    for bad_chirho in [
        vec!["b-chirho".to_owned(), "a-chirho".to_owned()],
        vec!["a-chirho".to_owned(), "a-chirho".to_owned()],
        vec!["merchant-chirho".to_owned()],
        vec![],
    ] {
        assert!(
            canonical_shard_set_line_chirho(&ShardSetRecordChirho {
                schema_chirho: SHARD_SET_SCHEMA_V1_CHIRHO.into(),
                seq_chirho: 0,
                prev_chirho: "x-chirho".into(),
                shard_log_id_chirho: SHARD_LOG_ID_CHIRHO.into(),
                owner_chirho: "merchant-chirho".into(),
                kind_chirho: "money-chirho".into(),
                op_chirho: ShardSetOpChirho::DeclareChirho {
                    shards_chirho: bad_chirho.clone()
                },
                owner_sig_chirho: String::new(),
            })
            .is_err(),
            "non-canonical shard set must refuse: {bad_chirho:?}"
        );
    }
}

#[test]
fn tampered_foreign_and_torn_declarations_fail_closed_chirho() {
    let storage_chirho = MemoryStorageChirho::default();
    let owner_chirho = OwnerRootSignerChirho;
    append_shard_set_op_chirho(
        &storage_chirho,
        &owner_chirho,
        &shard_path_chirho(),
        SHARD_LOG_ID_CHIRHO,
        "merchant-chirho",
        "money-chirho",
        ShardSetOpChirho::DeclareChirho {
            shards_chirho: declared_shards_chirho(),
        },
    )
    .unwrap();
    let clean_chirho = storage_chirho
        .read_all_chirho(&shard_path_chirho())
        .unwrap()
        .unwrap();
    // Tamper: swap a shard name inside the signed record.
    let tampered_chirho = String::from_utf8(clean_chirho.clone()).unwrap().replacen(
        "merchant-shard-0-chirho",
        "attacker-shard-0-chirho",
        1,
    );
    storage_chirho
        .atomic_write_chirho(&shard_path_chirho(), tampered_chirho.as_bytes())
        .unwrap();
    assert!(load_shard_sets_chirho(
        &storage_chirho,
        &owner_chirho,
        &shard_path_chirho(),
        SHARD_LOG_ID_CHIRHO,
    )
    .is_err());
    // Foreign signer: a JOURNAL-key-signed declaration must fail the OWNER root.
    let text_chirho = String::from_utf8(clean_chirho.clone()).unwrap();
    let line_chirho = text_chirho.lines().next().unwrap().to_owned();
    let mut record_chirho = parse_canonical_shard_set_line_chirho(&line_chirho).unwrap();
    record_chirho.owner_sig_chirho = String::new();
    let content_chirho =
        crate::shard_chirho::shard_set_signed_content_chirho(&record_chirho).unwrap();
    record_chirho.owner_sig_chirho = FakeJournalSignerChirho
        .sign_chirho(&content_chirho)
        .unwrap();
    let forged_line_chirho = canonical_shard_set_line_chirho(&record_chirho).unwrap();
    storage_chirho
        .atomic_write_chirho(
            &shard_path_chirho(),
            format!("{forged_line_chirho}\n").as_bytes(),
        )
        .unwrap();
    assert!(load_shard_sets_chirho(
        &storage_chirho,
        &owner_chirho,
        &shard_path_chirho(),
        SHARD_LOG_ID_CHIRHO,
    )
    .is_err());
    // Torn tail: config authority fails closed (no truncate-repair for routing authority).
    let mut torn_chirho = clean_chirho.clone();
    torn_chirho.extend_from_slice(b"{\"schema_chirho\":\"ledger-shard");
    storage_chirho
        .atomic_write_chirho(&shard_path_chirho(), &torn_chirho)
        .unwrap();
    assert!(load_shard_sets_chirho(
        &storage_chirho,
        &owner_chirho,
        &shard_path_chirho(),
        SHARD_LOG_ID_CHIRHO,
    )
    .is_err());
}

/// C1's attack test: a hostile actor funds `merchant-shard-99-chirho` (a name SHAPED like a
/// shard) — it must appear NOWHERE in the merchant's logical view, because shard-ness comes only
/// from the owner-signed declaration, never from the name.
#[test]
fn hostile_look_alike_shard_is_invisible_chirho() {
    let clock_chirho = SharedClockChirho {
        now_ms_chirho: Cell::new(1_000),
    };
    let fixture_chirho =
        JournalFixtureChirho::new_chirho("cluster-a-chirho", "money-chirho", "platform-a-chirho");
    let mut engine_chirho = LedgerJournalChirho::create_chirho(
        fixture_chirho.ports_chirho(&clock_chirho),
        fixture_chirho.path_chirho(),
        fixture_chirho.cluster_chirho.clone(),
        1,
    )
    .unwrap();
    engine_chirho
        .append_chirho(fixture_chirho.mint_chirho(500, "idem-hostile-mint"))
        .unwrap();
    // Legitimate: 10 to a DECLARED shard. Hostile: 40 to the look-alike.
    engine_chirho
        .append_chirho(fixture_chirho.transfer_chirho(
            "issuer-chirho",
            "merchant-shard-0-chirho",
            10,
            "idem-hostile-legit",
        ))
        .unwrap();
    engine_chirho
        .append_chirho(fixture_chirho.transfer_chirho(
            "issuer-chirho",
            "merchant-shard-99-chirho",
            40,
            "idem-hostile-fake",
        ))
        .unwrap();
    let storage_chirho = MemoryStorageChirho::default();
    let owner_chirho = OwnerRootSignerChirho;
    append_shard_set_op_chirho(
        &storage_chirho,
        &owner_chirho,
        &shard_path_chirho(),
        SHARD_LOG_ID_CHIRHO,
        "merchant-chirho",
        "money-chirho",
        ShardSetOpChirho::DeclareChirho {
            shards_chirho: declared_shards_chirho(),
        },
    )
    .unwrap();
    let sets_chirho = load_shard_sets_chirho(
        &storage_chirho,
        &owner_chirho,
        &shard_path_chirho(),
        SHARD_LOG_ID_CHIRHO,
    )
    .unwrap();
    assert_eq!(
        logical_net_chirho(
            &sets_chirho,
            engine_chirho.head_states_chirho(),
            "merchant-chirho",
            "money-chirho",
        ),
        10,
        "only the DECLARED shard counts; the look-alike's 40 is invisible"
    );
}

/// The C2 same-journal STRUCTURAL bench + C3 router discipline + consolidation:
/// N credits round-robined over K declared shards divide the per-row dependency-chain depth by K
/// (the head-row contention relief — the log append itself stays serial, stated per C2), debits
/// all chain on the parent by ROUTER DISCIPLINE (zero shard debits by construction), and
/// consolidation is ordinary Transfers that conserve the logical aggregate.
#[test]
fn round_robin_depth_scales_and_consolidation_conserves_chirho() {
    let clock_chirho = SharedClockChirho {
        now_ms_chirho: Cell::new(1_000),
    };
    let fixture_chirho =
        JournalFixtureChirho::new_chirho("cluster-a-chirho", "money-chirho", "platform-a-chirho");
    let mut engine_chirho = LedgerJournalChirho::create_chirho(
        fixture_chirho.ports_chirho(&clock_chirho),
        fixture_chirho.path_chirho(),
        fixture_chirho.cluster_chirho.clone(),
        1,
    )
    .unwrap();
    engine_chirho
        .append_chirho(fixture_chirho.mint_chirho(500, "idem-bench-mint"))
        .unwrap();
    let storage_chirho = MemoryStorageChirho::default();
    let owner_chirho = OwnerRootSignerChirho;
    append_shard_set_op_chirho(
        &storage_chirho,
        &owner_chirho,
        &shard_path_chirho(),
        SHARD_LOG_ID_CHIRHO,
        "merchant-chirho",
        "money-chirho",
        ShardSetOpChirho::DeclareChirho {
            shards_chirho: declared_shards_chirho(),
        },
    )
    .unwrap();
    let sets_chirho = load_shard_sets_chirho(
        &storage_chirho,
        &owner_chirho,
        &shard_path_chirho(),
        SHARD_LOG_ID_CHIRHO,
    )
    .unwrap();
    // Fan out 12 unit credits by the router; count per-row folds (the dependency-chain depth).
    let credits_chirho = 12_u64;
    let mut depth_chirho: BTreeMap<String, u64> = BTreeMap::new();
    for counter_chirho in 0..credits_chirho {
        let shard_chirho = route_credit_shard_chirho(
            &sets_chirho,
            "merchant-chirho",
            "money-chirho",
            counter_chirho,
        )
        .unwrap()
        .to_owned();
        engine_chirho
            .append_chirho(fixture_chirho.transfer_chirho(
                "issuer-chirho",
                &shard_chirho,
                1,
                &format!("idem-bench-c{counter_chirho}"),
            ))
            .unwrap();
        *depth_chirho.entry(shard_chirho).or_insert(0) += 1;
    }
    let max_sharded_depth_chirho = depth_chirho.values().copied().max().unwrap();
    assert_eq!(
        max_sharded_depth_chirho,
        credits_chirho / 3,
        "K=3 shards divide the hot row's fold chain by 3 (12 -> 4)"
    );
    assert_eq!(
        depth_chirho.len(),
        3,
        "round-robin touched every declared shard"
    );
    // The single-row baseline for contrast: the same 12 credits on ONE row chain to depth 12.
    let baseline_depth_chirho: u64 = credits_chirho;
    assert!(max_sharded_depth_chirho * 3 == baseline_depth_chirho);
    assert_eq!(
        logical_net_chirho(
            &sets_chirho,
            engine_chirho.head_states_chirho(),
            "merchant-chirho",
            "money-chirho",
        ),
        12
    );
    // CONSOLIDATION: ordinary shard -> parent Transfers; the logical aggregate is unchanged and
    // the parent now carries the whole balance.
    for (index_chirho, shard_chirho) in declared_shards_chirho().iter().enumerate() {
        engine_chirho
            .append_chirho(fixture_chirho.transfer_chirho(
                shard_chirho,
                "merchant-chirho",
                4,
                &format!("idem-bench-cons{index_chirho}"),
            ))
            .unwrap();
    }
    assert_eq!(
        logical_net_chirho(
            &sets_chirho,
            engine_chirho.head_states_chirho(),
            "merchant-chirho",
            "money-chirho",
        ),
        12,
        "consolidation conserves the logical aggregate"
    );
    // C3: debits SERIALIZE on the parent by router discipline — the merchant spends from the
    // parent row only; no shard row ever carries a debit in this flow.
    engine_chirho
        .append_chirho(fixture_chirho.transfer_chirho(
            "merchant-chirho",
            "issuer-chirho",
            12,
            "idem-bench-spend",
        ))
        .unwrap();
    for (account_chirho, post_chirho) in engine_chirho.head_states_chirho() {
        if declared_shards_chirho().contains(&account_chirho.owner_chirho) {
            assert_eq!(
                post_chirho.debits_total_chirho, 4,
                "shard debits are exactly the consolidation transfers, never spends"
            );
        }
    }
}

/// C2's explicit F3 dependency: the CROSS-JOURNAL regime (consolidate-home across clusters) rides
/// the counterpart row, which stays ExplicitlyUnsupported until the F3 finality verifier lands —
/// asserted as a live refusal, not a comment.
#[test]
fn cross_journal_consolidation_stays_f3_gated_chirho() {
    let clock_chirho = SharedClockChirho {
        now_ms_chirho: Cell::new(1_000),
    };
    let fixture_chirho =
        JournalFixtureChirho::new_chirho("cluster-a-chirho", "money-chirho", "platform-a-chirho");
    let mut engine_chirho = LedgerJournalChirho::create_chirho(
        fixture_chirho.ports_chirho(&clock_chirho),
        fixture_chirho.path_chirho(),
        fixture_chirho.cluster_chirho.clone(),
        1,
    )
    .unwrap();
    engine_chirho
        .append_chirho(fixture_chirho.mint_chirho(500, "idem-f3-mint"))
        .unwrap();
    engine_chirho
        .append_chirho(fixture_chirho.transfer_chirho(
            "issuer-chirho",
            "merchant-shard-0-chirho",
            10,
            "idem-f3-fund",
        ))
        .unwrap();
    let mut request_chirho = fixture_chirho.transfer_chirho(
        "merchant-shard-0-chirho",
        "merchant-chirho",
        10,
        "idem-f3-consolidate",
    );
    // The cross-cluster consolidate SHAPE: a counterpart claim on the credit leg.
    request_chirho.legs_chirho[1].counterpart_chirho = Some(CounterpartClaimChirho {
        transfer_id_chirho: TransferIdChirho("t-f3-chirho".into()),
        burn_chirho: FinalBurnRefChirho {
            source_money_group_chirho: MoneyGroupIdChirho("mg-chirho".into()),
            source_cluster_chirho: ClusterIdChirho("cluster-b-chirho".into()),
            source_epoch_chirho: 1,
            source_seq_chirho: 1,
            source_record_digest_chirho: DigestChirho("burn-chirho".into()),
            finality_proof_ref_chirho: DigestChirho("proof-chirho".into()),
        },
        amount_chirho: 10,
        kind_policy_ref_chirho: AssetKindRefChirho(DigestChirho(
            fixture_chirho.policy_ref_chirho.clone(),
        )),
        src_chirho: LogIdChirho::new_chirho("merchant-shard-0-chirho", "money-chirho"),
        dst_money_group_chirho: MoneyGroupIdChirho("mg-chirho".into()),
        dst_cluster_chirho: ClusterIdChirho("cluster-a-chirho".into()),
        dst_chirho: LogIdChirho::new_chirho("merchant-chirho", "money-chirho"),
        channel_chirho: SettlementChannelIdChirho("chan-chirho".into()),
        nullifier_chirho: CounterpartNullifierChirho(DigestChirho("null-chirho".into())),
    });
    let refusal_chirho = engine_chirho.append_chirho(request_chirho);
    assert!(
        matches!(
            refusal_chirho,
            Err(cairn_ledger_log_chirho::journal_chirho::JournalErrorChirho::AdmissionChirho {
                reject_chirho:
                    cairn_ledger_log_chirho::admission_chirho::AdmissionRejectChirho::UnsupportedOperationChirho
            })
        ),
        "the counterpart row must refuse until the F3 verifier increment"
    );
}
